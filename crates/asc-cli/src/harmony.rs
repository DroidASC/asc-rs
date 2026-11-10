//! HarmonyOS programs (`.hap` / `.hsp` / `.app` / `.abc`) behind the commands
//! of the DEX side: `listclass`, `getclass` / `disassemble`, `getmanifest`,
//! `manifest-summary`, `resources`, `xml` (the text files of a package),
//! `findrefs` (string, prop, global, import, method, number, call, all,
//! rules), `callgraph` and `hierarchy`.
//!
//! This is a thin dispatch ahead of the layer both formats will share. The
//! engine comes from [`Io::harmony`]: opened for this command in a one-shot
//! process, kept open between commands by the daemon ([`crate::daemon`]). It
//! keeps nothing on disk, so the disk caches take no part. What the engine
//! cannot answer yet fails with one line that names what it can.

use crate::output::Io;
use crate::{ClassArgs, Command, Common, FieldAccessArg, Find, EXIT_OK, EXIT_PARTIAL, RESOURCE_SEARCH_ROWS};
use asc_ark_engine::{
    Access, CallQuery, CallRoots, ClassQuery, Direction, Document, Engine, EngineError, EntryStatus, HierarchyQuery, Lineage, ListOptions,
    Manifest, NameFilter, Pattern, Query, RefBatch, RefContext, ResourceField, ResourceTables,
};
use asc_mcp::harmony::{function_roots, no_callers_hint, no_class_hint, no_leaf_hint, rule_roots, TreeText};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// The `findrefs` kinds that work on a HarmonyOS program.
const SEARCHES: &str = "string, prop, global, import, method, number, call, all, rules";
/// What `callgraph` takes on a HarmonyOS program.
const WALKS: &str =
    "[RECORD] FUNCTION or --to RULE, --from RULE, --unless RULE, --callees, --depth, --max-nodes, --no-defines, --unresolved, --entry";

/// What a `findrefs` kind or option the engine does not have says.
fn unsupported_search(what: &str) -> String {
    format!("findrefs {what} is not supported for HarmonyOS programs yet (supported: findrefs {SEARCHES})")
}

/// What `callgraph` needs to be told on a HarmonyOS program.
fn no_target() -> String {
    format!("callgraph needs a target (callgraph takes: {WALKS}; RECORD->FUNCTION as result rows print it is a target too)")
}

fn dex_only(flag: &str) -> String {
    format!("{flag} is DEX-only")
}

/// Run a one-shot command on the HarmonyOS program it names: the exit status.
pub(crate) fn run(io: &mut Io<'_>, common: &Common, command: Command, t_start: Instant) -> Result<u8, String> {
    io.window = common.window();
    io.spill = common.spill();
    let code = match command {
        Command::Listclass { prefix, all, entry, output, apk_path } => {
            let engine = open(io, common, &apk_path)?;
            let options = ListOptions { filter: prefix.map(NameFilter::Prefix), all, entry };
            listclass(io, &engine, &options, output.as_ref())?;
            EXIT_OK
        }
        Command::Getclass { output, no_debug_info: _, dump_dex, method_signature, res_names, entry, apk_path, dalvik_class } => {
            // `--no-debug-info` holds as it is: the disassembly has no debug directives.
            let args =
                ClassArgs { output, tee: true, debug_info: false, dump_dex, method_signature, res_names, entry, apk_path, dalvik_class };
            getclass(io, common, &args)?;
            EXIT_OK
        }
        Command::Disassemble { output, debuginfo, method_signature, res_names, dump_dex, entry, apk_path, dalvik_class } => {
            let args = ClassArgs {
                output,
                tee: false,
                debug_info: debuginfo,
                dump_dex,
                method_signature,
                res_names,
                entry,
                apk_path,
                dalvik_class,
            };
            getclass(io, common, &args)?;
            EXIT_OK
        }
        Command::Findrefs { apk_path, context, context_method, access, entry, find } => {
            let context = match (context, context_method) {
                (Some(asc_engine::RefContext::Lines(lines)), _) => RefContext::Lines(lines),
                (Some(asc_engine::RefContext::Method), _) | (None, true) => RefContext::Method,
                (Some(asc_engine::RefContext::None), _) | (None, false) => RefContext::None,
            };
            match search(io, find, access)? {
                Search::Refs { query, output } => {
                    let engine = open(io, common, &apk_path)?;
                    findrefs(io, &engine, &query, entry.as_deref(), context, output.as_ref())?
                }
                Search::Rules { specs, rules, output } => {
                    let engine = open(io, common, &apk_path)?;
                    let asked = Rules { specs: &specs, rules: &rules, entry: entry.as_deref(), context };
                    findrefs_rules(io, &engine, &asked, output.as_ref())?
                }
                Search::Requests { pattern, output } => {
                    let engine = open(io, common, &apk_path)?;
                    module_requests(io, &engine, &pattern, entry.as_deref(), output.as_ref())?;
                    EXIT_OK
                }
            }
        }
        Command::Getmanifest { output, resolve, file, apk_path } => {
            if resolve {
                return Err(format!(
                    "{}: module.json is printed as it is; manifest-summary puts what a $type:name reference stands for behind it",
                    dex_only("getmanifest --resolve")
                ));
            }
            let document = document(file.as_deref())?.unwrap_or(Document::Module);
            let engine = open(io, common, &apk_path)?;
            getmanifest(io, &engine, &apk_path, document, output.as_ref())?;
            EXIT_OK
        }
        Command::ManifestSummary { json, output, file, apk_path } => {
            let document = document(file.as_deref())?;
            let engine = open(io, common, &apk_path)?;
            manifest_summary(io, &engine, &apk_path, document, json, output.as_ref())?;
            EXIT_OK
        }
        Command::Resources { search, literal, field, resolve, output, apk_path, query } => {
            // Read before the program is opened: a bad option fails the same way whatever the program holds.
            let field = match field.as_str() {
                "name" => ResourceField::Name,
                "value" => ResourceField::Value,
                "any" => ResourceField::Any,
                other => return Err(format!("--in must be name, value or any, not {other}")),
            };
            let asked = match (search, query) {
                (Some(text), _) => Asked::Search { pattern: pattern(&text, literal, false)?, field },
                (None, Some(query)) if resolve => Asked::Resolve(query),
                (None, Some(query)) => Asked::Resource(query),
                (None, None) => Asked::Everything,
            };
            let engine = open(io, common, &apk_path)?;
            resources(io, &engine, &apk_path, &asked, output.as_ref())?;
            EXIT_OK
        }
        Command::Xml { output, apk_path, path } => {
            let engine = open(io, common, &apk_path)?;
            package_files(io, &engine, &path, output.as_ref())?;
            EXIT_OK
        }
        Command::Callgraph {
            output,
            callees,
            depth,
            max_nodes,
            virtual_calls,
            to,
            from,
            unless,
            no_defines,
            unresolved,
            entry,
            apk_path,
            class,
            method,
        } => {
            if virtual_calls {
                return Err(dex_only("--virtual"));
            }
            let parsed = |arg: &str, spec: &str| io.harmony_rule(spec).map_err(|e| format!("{arg}: {e}"));
            let mut from = from.map(|spec| parsed("--from", &spec)).transpose()?;
            let unless = unless.iter().map(|spec| parsed("--unless", spec)).collect::<Result<Vec<_>, _>>()?;
            let to_rule = to.as_deref().map(|spec| parsed("--to", spec)).transpose()?;
            let target = CallTarget { class, method, to: to_rule, entry };
            let mut direction = if callees { Direction::Callees } else { Direction::Callers };
            let roots = match target.roots(direction)? {
                Some(_) if from.is_some() && callees => return Err("--from keeps caller paths: leave out --callees".into()),
                Some(roots) => roots,
                // As on the DEX side: `--from` alone walks the callees of the functions it matches.
                None => {
                    direction = Direction::Callees;
                    CallRoots::Matching(from.take().ok_or_else(no_target)?)
                }
            };
            if unresolved && direction == Direction::Callers {
                return Err("--unresolved lists callees: add --callees".into());
            }
            let query = CallQuery { depth, max_nodes, defines: !no_defines, unresolved, from, unless, ..CallQuery::new(roots, direction) };
            let engine = open(io, common, &apk_path)?;
            callgraph(io, &engine, &query, to.as_deref(), output.as_ref())?
        }
        Command::Hierarchy { output, supers, depth, max_nodes, method, entry, apk_path, class } => {
            let direction = if supers { Lineage::Supers } else { Lineage::Subclasses };
            let query = HierarchyQuery { class, entry, direction, depth, max_nodes, method };
            let engine = open(io, common, &apk_path)?;
            hierarchy(io, &engine, &query, output.as_ref())?
        }
        Command::Mcp { .. } | Command::Cache { .. } | Command::Daemon { .. } | Command::Config { .. } => {
            unreachable!("only a command with a program path is dispatched by format")
        }
    };
    if common.debug {
        io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
    }
    Ok(code)
}

/// Open the program and report what it leaves out (encrypted entries,
/// packages without code), as the DEX side reports its program notes. That
/// encrypted entries are read from decrypted files is one `# note:` line,
/// however many there are: nothing is left out.
fn open(io: &mut Io<'_>, common: &Common, path: &Path) -> Result<Arc<Engine>, String> {
    let engine = io.harmony(common, path).map_err(|e| e.to_string())?;
    for note in engine.notes() {
        io.note(format_args!("# warning: {note}"));
    }
    if let Some(note) = engine.stand_in_note() {
        io.note(format_args!("# note: {note}"));
    }
    Ok(engine)
}

/// What a search or listing that `--entry` keeps to part of the program
/// says when it fails: an entry that is not there is told what is.
fn entry_error(engine: &Engine, error: &EngineError) -> String {
    match error {
        EngineError::NoEntry(_) => format!("{error} ({})", asc_mcp::harmony::entries_hint(engine)),
        other => other.to_string(),
    }
}

/// One record per line; a program of several ABC entries also names the entry.
fn listclass(io: &mut Io<'_>, engine: &Engine, options: &ListOptions, output: Option<&PathBuf>) -> Result<(), String> {
    let records = engine.list_classes(options).map_err(|e| entry_error(engine, &e))?;
    let with_entry = engine.has_several_entries();
    let text: String = records.iter().map(|record| record.line(with_entry) + "\n").collect();
    match output {
        Some(path) => io.write_file(path, text.as_bytes()),
        None if text.is_empty() => Ok(()),
        None => io.emit_records(&text, None),
    }
}

/// `--file NAME`: the document it names.
fn document(file: Option<&str>) -> Result<Option<Document>, String> {
    file.map(|name| name.parse::<Document>().map_err(|e| format!("--file: {e}"))).transpose()
}

/// The manifests of the program, which must have `document` (any, when
/// `None`). `given`: the program's path as the command names it, which the
/// error shows (a resident engine knows the program by its full path).
fn manifest(engine: &Engine, given: &Path, document: Option<Document>) -> Result<Manifest, String> {
    let missing = |document, bare| EngineError::NoManifest { path: given.to_path_buf(), document, bare }.to_string();
    let manifest = engine.manifest().map_err(|e| match e {
        EngineError::NoManifest { document, bare, .. } => missing(document, bare),
        other => other.to_string(),
    })?;
    match document {
        Some(document) if !manifest.has(document) => Err(missing(Some(document.file_name()), false)),
        _ => Ok(manifest),
    }
}

/// The document as JSON. A program of several packages prints one after the
/// other, each under a `# PACKAGE/NAME` line.
fn getmanifest(io: &mut Io<'_>, engine: &Engine, given: &Path, document: Document, output: Option<&PathBuf>) -> Result<(), String> {
    let manifest = manifest(engine, given, Some(document))?;
    let several = manifest.has_several_packages();
    let mut text = String::new();
    for found in manifest.documents(document) {
        if several {
            text.push_str(&format!("# {}\n", found.heading()));
        }
        text.push_str(found.text.trim_end());
        text.push('\n');
    }
    io.write_output(output, &text)?;
    io.emit_records(&text, output)
}

/// One fact per line; a program of several packages starts each line with
/// the package, as findrefs rows start with their entry.
fn manifest_summary(
    io: &mut Io<'_>,
    engine: &Engine,
    given: &Path,
    document: Option<Document>,
    json: bool,
    output: Option<&PathBuf>,
) -> Result<(), String> {
    let manifest = manifest(engine, given, document)?;
    let text = if json {
        if document.is_some() {
            return Err("--json is the whole summary: leave out --file".into());
        }
        format!("{:#}\n", manifest.json())
    } else {
        let several = manifest.has_several_packages();
        manifest.summary_lines(document).iter().map(|line| line.line(several) + "\n").collect()
    };
    io.write_output(output, &text)?;
    if text.is_empty() {
        return Ok(());
    }
    io.emit_records(&text, output)
}

/// What a `resources` command line asks for.
enum Asked {
    /// No QUERY and no --search: every value.
    Everything,
    /// QUERY: every value of one resource.
    Resource(String),
    /// QUERY with --resolve: the resource behind its references.
    Resolve(String),
    Search {
        pattern: Pattern,
        field: ResourceField,
    },
}

/// The resource indexes of the program. `given`: the program's path as the
/// command names it, which the error shows (a resident engine knows the
/// program by its full path). Packages left out are named on stderr.
fn resource_tables<'e>(io: &mut Io<'_>, engine: &'e Engine, given: &Path) -> Result<ResourceTables<'e>, String> {
    let tables = engine.resources().map_err(|e| match e {
        EngineError::NoResources { notes, .. } => EngineError::NoResources { path: given.to_path_buf(), notes }.to_string(),
        other => other.to_string(),
    })?;
    for note in tables.notes() {
        io.note(format_args!("# warning: {note}"));
    }
    Ok(tables)
}

/// What a query that names no resource of the program says.
fn no_resource(error: &EngineError) -> String {
    match error {
        // The packages left out were named when the indexes were read.
        EngineError::NotFound { what: "resource", name, .. } => {
            format!("resource {name} not found (--search REGEX finds resources by name or value)")
        }
        other => other.to_string(),
    }
}

/// One row per value, `0x01000000 string/app_name [base] "Shop"`; a program
/// of several packages starts each row with the package, as findrefs rows
/// start with their entry. `--resolve` prints the reference chain ahead of
/// the row it ends at.
fn resources(io: &mut Io<'_>, engine: &Engine, given: &Path, asked: &Asked, output: Option<&PathBuf>) -> Result<(), String> {
    let tables = resource_tables(io, engine, given)?;
    let several = tables.has_several_packages();
    // With a window every match goes through it (the file holds them all).
    let search_cap = if output.is_none() && !io.window.is_everything() { usize::MAX } else { RESOURCE_SEARCH_ROWS };
    let mut note = None;
    let mut sink = io.sink(output, output.is_none())?;
    match asked {
        Asked::Search { pattern, field } => {
            let (rows, total) = tables.search(pattern, *field, search_cap);
            rows.iter().for_each(|row| sink.line(&row.line(several)));
            if total > rows.len() {
                note =
                    Some(format!("Note: {} of {total} matches shown; with --limit or --max-bytes every match goes to a file", rows.len()));
            }
        }
        Asked::Resolve(query) => {
            for resolved in tables.resolve(query).map_err(|e| no_resource(&e))? {
                sink.line(&resolved.chain_line(several));
                sink.line(&resolved.row.line(several));
            }
        }
        Asked::Resource(query) => tables.lookup(query).map_err(|e| no_resource(&e))?.iter().for_each(|row| sink.line(&row.line(several))),
        Asked::Everything => tables.for_each(|row| sink.line(&row.line(several))),
    }
    let io_result = sink.finish();
    if let Some(note) = note {
        io.note(note);
    }
    io_result
}

/// `xml`: the text files `target` names (a file resource, `$profile:NAME`,
/// or a path inside the package), as they are. A program of several
/// packages prints one after the other, each under a `# PACKAGE/PATH` line.
fn package_files(io: &mut Io<'_>, engine: &Engine, target: &str, output: Option<&PathBuf>) -> Result<(), String> {
    let files = engine.package_files(target).map_err(|e| match &e {
        EngineError::NotFound { what: "file", .. } => {
            format!("{e} (give a path inside the package, e.g. resources/base/profile/main_pages.json, or a file resource: $profile:main_pages)")
        }
        _ => no_resource(&e),
    })?;
    let several = engine.has_several_packages();
    let mut text = String::new();
    for file in &files {
        if several {
            text.push_str(&format!("# {}/{}\n", file.package, file.path));
        }
        text.push_str(&file.text);
        if !file.text.ends_with('\n') {
            text.push('\n');
        }
    }
    io.write_output(output, &text)?;
    io.emit_records(&text, output)
}

/// What `getclass` is asked for: a record, or one function of it.
struct Target<'a> {
    record: &'a str,
    function: Option<&'a str>,
}

impl<'a> Target<'a> {
    /// `RECORD` with `--method FUNCTION`, or the location column of a
    /// findrefs row pasted as it is: `RECORD->FUNCTION` or
    /// `RECORD->FUNCTION+0xPC`.
    fn parse(class: &'a str, method: Option<&'a str>) -> Target<'a> {
        if method.is_some() {
            return Target { record: class, function: method };
        }
        match class.split_once("->") {
            Some((record, function)) => Target { record, function: Some(without_pc(function)) },
            None => Target { record: class, function: None },
        }
    }
}

/// `function` without the `+0xPC` a findrefs row appends to it.
fn without_pc(function: &str) -> &str {
    match function.rsplit_once("+0x") {
        Some((name, pc)) if !name.is_empty() && !pc.is_empty() && pc.bytes().all(|b| b.is_ascii_hexdigit()) => name,
        _ => function,
    }
}

/// Whether two of the `entry | record` candidates of an ambiguous record are
/// one record in different entries: more of its path cannot tell those apart.
fn several_entries_define(candidates: &[String]) -> bool {
    let records: Vec<&str> = candidates.iter().filter_map(|candidate| candidate.split_once(" | ")).map(|(_, record)| record).collect();
    records.iter().enumerate().any(|(i, record)| records[..i].contains(record))
}

fn getclass(io: &mut Io<'_>, common: &Common, args: &ClassArgs) -> Result<(), String> {
    if args.dump_dex.is_some() {
        return Err(dex_only("--dump-dex"));
    }
    if args.debug_info {
        return Err(dex_only("--debuginfo"));
    }
    let engine = open(io, common, &args.apk_path)?;
    let target = Target::parse(&args.dalvik_class, args.method_signature.as_deref());
    let query = ClassQuery { record: target.record, function: target.function, entry: args.entry.as_deref() };
    let mut source = engine.get_class(&query).map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if several_entries_define(candidates) => {
            format!("{e}\n(name the entry, the first column, with --entry)")
        }
        _ => e.to_string(),
    })?;
    if args.res_names {
        engine.annotate_resource_ids(&mut source);
    }
    if common.debug {
        io.note(format_args!("[DEBUG] Hit ABC: {}", source.entry));
    }
    io.write_output(args.output.as_ref(), &source.text)?;
    if args.output.is_some() && !args.tee {
        return Ok(());
    }
    io.emit_records(&source.text, args.output.as_ref())
}

/// What a `findrefs` command line asks for.
enum Search {
    Refs {
        query: Query,
        output: Option<PathBuf>,
    },
    /// `import --requests`: the distinct module requests.
    Requests {
        pattern: Pattern,
        output: Option<PathBuf>,
    },
    /// `rules`: several rules, each as it was written.
    Rules {
        specs: Vec<String>,
        rules: Vec<Query>,
        output: Option<PathBuf>,
    },
}

/// A name pattern: a regex, or with `--literal` / `--exact` plain text.
fn pattern(text: &str, literal: bool, exact: bool) -> Result<Pattern, String> {
    match (literal, exact) {
        (_, true) => Ok(Pattern::exact(text)),
        (true, false) => Ok(Pattern::contains(text)),
        (false, false) => Pattern::regex(text).map_err(|e| e.to_string()),
    }
}

/// As [`pattern`], for the name of a property, a global or a function:
/// `=NAME` is the exact name too, as a condition writes it.
fn name_pattern(text: &str, literal: bool, exact: bool) -> Result<Pattern, String> {
    match text.strip_prefix('=') {
        Some(name) if !literal && !exact => Ok(Pattern::exact(name)),
        _ => pattern(text, literal, exact),
    }
}

impl From<FieldAccessArg> for Access {
    fn from(access: FieldAccessArg) -> Access {
        match access {
            FieldAccessArg::Read => Access::Read,
            FieldAccessArg::Write => Access::Write,
            FieldAccessArg::Define => Access::Define,
            FieldAccessArg::Call => Access::Call,
        }
    }
}

/// The kind of a condition as it is written (`!` aside), when the engine has it.
fn known_kind(spec: &str) -> Result<(), String> {
    let spec = spec.trim_start().trim_start_matches('!').trim_start();
    let kind = spec.split_once(':').map_or(spec, |(kind, _)| kind).trim();
    // Not `KIND:VALUE` at all: the engine says what is.
    if Query::KINDS.contains(&kind) || !spec.contains(':') || !kind.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Ok(());
    }
    Err(format!(
        "findrefs {kind}: is not supported for HarmonyOS programs yet (supported: {})",
        Query::KINDS.map(|kind| format!("{kind}:")).join(", ")
    ))
}

/// One condition of `findrefs all`, without its `!`.
fn condition(io: &Io<'_>, spec: &str) -> Result<Query, String> {
    known_kind(spec)?;
    match io.harmony_rule(spec)? {
        Query::All(_) => Err(format!("{spec:?} is several conditions; give one KIND:VALUE here")),
        query => Ok(query),
    }
}

/// One rule of `findrefs rules`.
fn rule(io: &Io<'_>, spec: &str) -> Result<Query, String> {
    Query::rule_parts(spec).into_iter().try_for_each(known_kind)?;
    io.harmony_rule(spec)
}

/// The search `find` asks for and its `-o` file.
fn search(io: &Io<'_>, find: Find, access: Option<FieldAccessArg>) -> Result<Search, String> {
    if access.is_some() && !matches!(find, Find::Prop { .. } | Find::Global { .. }) {
        return Err("--access is only valid for `findrefs prop` and `findrefs global` on HarmonyOS programs".into());
    }
    let access = access.map(Access::from);
    let refs = |query, output| Ok(Search::Refs { query, output });
    let kind = match find {
        Find::String { output, literal: true, value } => return refs(Query::string_literal(value), output),
        Find::String { output, literal: false, value } => return refs(Query::string_regex(&value).map_err(|e| e.to_string())?, output),
        Find::Prop { output, literal, exact, name } => {
            return refs(Query::Prop { name: name_pattern(&name, literal, exact)?, access }, output)
        }
        Find::Global { output, literal, exact, name } => {
            return refs(Query::global(name_pattern(&name, literal, exact)?, access).map_err(|e| e.to_string())?, output);
        }
        Find::Import { output, literal, decl, requests, value } => {
            let query = Query::import(&value, literal).map_err(|e| e.to_string())?;
            return match query {
                Query::Import { request, name: None, .. } if requests => Ok(Search::Requests { pattern: request, output }),
                Query::Import { .. } if requests => Err("--requests lists module requests: leave out the #NAME".into()),
                Query::Import { request, name, .. } => refs(Query::Import { request, name, declarations_only: decl }, output),
                _ => Err(unsupported_search("import")),
            };
        }
        Find::Method { fuzzy_class: true, .. } => return Err(dex_only("--fuzzy-class")),
        Find::Method { name: None, .. } => return Err("findrefs method needs a function name on a HarmonyOS program".into()),
        Find::Method { output, name: Some(name), class_name, fuzzy_class: false, exact } => {
            // RECORD->FUNCTION, as a result row prints it, or the record in --class.
            let spec = match class_name {
                Some(record) => format!("{record}->{name}"),
                None => without_pc(&name).to_owned(),
            };
            return refs(
                Query::method(&spec, |name| name_pattern(name, false, exact).map_err(EngineError::Query)).map_err(|e| e.to_string())?,
                output,
            );
        }
        Find::Number { output, value } => return refs(Query::Number(value.parse().map_err(|e: EngineError| e.to_string())?), output),
        // `call '{RULE}'`: the calls of the functions a rule matches, as in a condition.
        Find::Call { output, literal: false, path } if path.starts_with('{') => {
            return refs(condition(io, &format!("call:{path}"))?, output)
        }
        Find::Call { output, literal, path } => return refs(Query::Call(pattern(&path, literal, false)?), output),
        Find::All { output, none, conditions } => {
            // `!COND` among the conditions is one more --none.
            let (excluded, conditions): (Vec<String>, Vec<String>) = conditions.into_iter().partition(|spec| spec.starts_with('!'));
            let parse = |specs: &[String]| {
                specs.iter().map(|spec| condition(io, spec.strip_prefix('!').unwrap_or(spec))).collect::<Result<Vec<_>, _>>()
            };
            let all = parse(&conditions)?;
            let mut none = parse(&none)?;
            none.extend(parse(&excluded)?);
            // One condition is that query itself, as on the DEX side.
            return refs(Query::compound(all, none).map_err(|e| e.to_string())?, output);
        }
        Find::Rules { output, file, rules: mut specs } => {
            if let Some(file) = &file {
                let text = std::fs::read_to_string(io.path(file)).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
                specs.extend(text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')).map(String::from));
            }
            if specs.is_empty() {
                return Err("findrefs rules needs at least one rule".into());
            }
            let rules = specs.iter().map(|spec| rule(io, spec)).collect::<Result<Vec<_>, _>>()?;
            return Ok(Search::Rules { specs, rules, output });
        }
        Find::Type { .. } => "type",
        Find::Extends { .. } => "extends",
        Find::Impl { .. } => "impl",
        Find::Field { .. } => "field",
    };
    Err(unsupported_search(kind))
}

/// `findrefs import --requests`: one line per distinct module request.
fn module_requests(
    io: &mut Io<'_>,
    engine: &Engine,
    pattern: &Pattern,
    entry: Option<&str>,
    output: Option<&PathBuf>,
) -> Result<(), String> {
    let requests = engine.module_requests_in(Some(pattern), entry).map_err(|e| entry_error(engine, &e))?;
    let with_entry = engine.has_several_entries();
    let text: String = requests.iter().map(|request| request.line(with_entry) + "\n").collect();
    io.write_output(output, &text)?;
    if text.is_empty() {
        return Ok(());
    }
    io.emit_records(&text, output)
}

/// The target of a `callgraph` command line.
struct CallTarget {
    class: Option<String>,
    method: Option<String>,
    /// `--to RULE`, parsed.
    to: Option<Query>,
    entry: Option<String>,
}

impl CallTarget {
    /// The roots of a walk in `direction`: the function `RECORD FUNCTION`
    /// names, or one argument as result rows print it (`RECORD->FUNCTION`,
    /// `RECORD->FUNCTION+0xPC`) or a function name alone; or what `--to
    /// RULE` matches: the callee paths of a lone `call:PATTERN`, else the
    /// functions of the rule. `None` without a target.
    fn roots(self, direction: Direction) -> Result<Option<CallRoots>, String> {
        let entry = self.entry.as_deref();
        match (self.class, self.method, self.to) {
            (None, _, None) => Ok(None),
            (Some(_), _, Some(_)) => Err("give the target as [RECORD] FUNCTION or as --to RULE, not both".into()),
            (None, _, Some(_)) if entry.is_some() => Err("--entry picks the root function: it does not go with --to".into()),
            (None, _, Some(Query::Call(_))) if direction == Direction::Callees => {
                Err("--to call:PATTERN walks the callers of a callee path: leave out --callees".into())
            }
            (None, _, Some(to)) => Ok(Some(rule_roots(to))),
            (Some(record), Some(function), None) => Ok(Some(function_roots(Some(&record), &function, entry))),
            (Some(spec), None, None) => Ok(Some(function_roots(None, &spec, entry))),
        }
    }
}

/// ABC entries no query reads (encrypted, damaged): named when the program opened.
fn unreadable_entries(engine: &Engine) -> usize {
    engine.entries().filter(|entry| entry.status != EntryStatus::Readable).count()
}

/// As [`unreadable_entries`], among the entries `--entry` keeps the search to.
fn unreadable_entries_in(engine: &Engine, entry: Option<&str>) -> Result<usize, String> {
    let entries = engine.entries_in(entry).map_err(|e| entry_error(engine, &e))?;
    Ok(entries.into_iter().filter(|entry| entry.status != EntryStatus::Readable).count())
}

/// The tree of `query`: the exit status, [`EXIT_PARTIAL`] when part of the
/// program could not be walked. `to`: the `--to` rule, for the hint of a
/// walk that found no callee path.
fn callgraph(io: &mut Io<'_>, engine: &Engine, query: &CallQuery, to: Option<&str>, output: Option<&PathBuf>) -> Result<u8, String> {
    let mut tree = engine.call_graph(query, io.cancel).map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if several_entries_define(candidates) => {
            format!("{e}\n(name the entry, the first column, with --entry)")
        }
        EngineError::NotFound { what: "function", .. } => format!("{e} (`findrefs method NAME` lists the functions a name defines)"),
        _ => e.to_string(),
    })?;
    // Said on stderr when the program opened.
    tree.notes.clear();
    let shown = TreeText::of(&tree, engine.has_several_entries());
    io.emit_tree(output, &shown.lines, &shown.footer)?;
    // Without rows though no `--from` dropped them: no callee path matched.
    if let (Some(to), true, CallRoots::Leaf(_)) = (to, tree.rows.is_empty() && tree.reached.is_none(), &query.roots) {
        io.note(format_args!("hint: {}", no_leaf_hint(to, "findrefs call")));
    } else if let Some(hint) = no_callers_hint(&tree, "`findrefs prop NAME --exact --access call`") {
        io.note(format_args!("hint: {hint}"));
    }
    let unsearched = unreadable_entries(engine);
    if unsearched == 0 {
        return Ok(EXIT_OK);
    }
    io.note(format_args!("Warning: {unsearched} ABC entr{} could not be searched", if unsearched == 1 { "y" } else { "ies" }));
    Ok(EXIT_PARTIAL)
}

/// The tree of `query`, then the definitions of the method it asks for: the
/// exit status, [`EXIT_PARTIAL`] when part of the program could not be read.
fn hierarchy(io: &mut Io<'_>, engine: &Engine, query: &HierarchyQuery, output: Option<&PathBuf>) -> Result<u8, String> {
    let mut tree = engine.hierarchy(query, io.cancel).map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if several_entries_define(candidates) => {
            format!("{e}\n(name the entry, the first column, with --entry)")
        }
        EngineError::NotFound { what: "class" | "parent path", .. } => format!("{e} ({})", no_class_hint("findrefs method NAME")),
        _ => e.to_string(),
    })?;
    // Said on stderr when the program opened.
    tree.notes.clear();
    let (rows, footer) = tree.text(engine.has_several_entries());
    io.emit_tree(output, &rows, &footer)?;
    let unsearched = unreadable_entries(engine);
    if unsearched == 0 {
        return Ok(EXIT_OK);
    }
    io.note(format_args!("Warning: {unsearched} ABC entr{} could not be searched", if unsearched == 1 { "y" } else { "ies" }));
    Ok(EXIT_PARTIAL)
}

/// One row per reference, entry by entry in program order (of the entries
/// `entry` names, when given): the exit status, [`EXIT_PARTIAL`] when part of
/// what was to be searched could not be.
fn findrefs(
    io: &mut Io<'_>,
    engine: &Engine,
    query: &Query,
    entry: Option<&str>,
    context: RefContext,
    output: Option<&PathBuf>,
) -> Result<u8, String> {
    // Before the output file is made: an entry that is not there is the whole answer.
    let unreadable = unreadable_entries_in(engine, entry)?;
    let cancel = io.cancel;
    let mut sink = io.sink(output, true)?;
    let mut errors = Vec::new();
    let summary = engine
        .find_refs_in(query, entry, cancel, &mut |mut batch| {
            engine.fill_context(&batch.entry_name, &mut batch.rows, context);
            for row in &batch.rows {
                sink.line(&row.text(&batch.entry_name));
            }
            sink.flush_stdout();
            if let Some(error) = batch.error {
                errors.push(format!("{}: {error}", batch.entry_name));
            }
        })
        .map_err(|e| e.to_string())?;
    let total = summary.total_results;
    let io_result = sink.finish();
    for error in &errors {
        io.note(format_args!("Warning: {error}"));
    }
    if total == 0 && errors.is_empty() {
        for hint in engine.no_results_hints(query, cancel) {
            io.note(format_args!("hint: {hint}"));
        }
        if let Some(entry) = entry {
            let all = engine.entries().count();
            io.note(format_args!("hint: --entry {entry} kept the search to {} of the {all} abc entries", summary.entries));
        }
    }
    io_result?;
    // Entries left out whole (encrypted, damaged) were named when the program opened.
    let unsearched = unreadable + errors.len();
    if unsearched == 0 {
        return Ok(EXIT_OK);
    }
    io.note(format_args!("Warning: {unsearched} ABC entr{} could not be searched", if unsearched == 1 { "y" } else { "ies" }));
    Ok(EXIT_PARTIAL)
}

/// What `findrefs rules` asks for.
struct Rules<'a> {
    /// The rules as they were written, for the `# rN` lines.
    specs: &'a [String],
    rules: &'a [Query],
    entry: Option<&'a str>,
    context: RefContext,
}

/// `findrefs rules`: the rows of every rule, prefixed `rN | `, entry by
/// entry as on the DEX side, between a `# rN RULE` line and a `# rN N
/// results` line per rule. Each rule is one search of the program.
fn findrefs_rules(io: &mut Io<'_>, engine: &Engine, asked: &Rules<'_>, output: Option<&PathBuf>) -> Result<u8, String> {
    let unreadable = unreadable_entries_in(engine, asked.entry)?;
    let cancel = io.cancel;
    let mut found: Vec<Vec<RefBatch>> = Vec::with_capacity(asked.rules.len());
    for rule in asked.rules {
        let mut batches = Vec::new();
        engine.find_refs_in(rule, asked.entry, cancel, &mut |batch| batches.push(batch)).map_err(|e| e.to_string())?;
        found.push(batches);
    }
    let mut sink = io.sink(output, true)?;
    for (index, spec) in asked.specs.iter().enumerate() {
        sink.comment(&format!("# r{} {spec}", index + 1));
    }
    let mut errors = Vec::new();
    let mut totals = vec![0usize; found.len()];
    let entries = found.iter().map(Vec::len).max().unwrap_or(0);
    for entry in 0..entries {
        for (index, batches) in found.iter_mut().enumerate() {
            let Some(batch) = batches.get_mut(entry) else { continue };
            if let Some(error) = &batch.error {
                errors.push(format!("{}: {error}", batch.entry_name));
            }
            totals[index] += batch.rows.len();
            engine.fill_context(&batch.entry_name, &mut batch.rows, asked.context);
            for row in &batch.rows {
                let text = row.text(&batch.entry_name);
                // Context lines keep their indentation after the prefix.
                let record: Vec<String> = text
                    .lines()
                    .enumerate()
                    .map(|(line, text)| if line == 0 { format!("r{} | {text}", index + 1) } else { format!("r{} |{text}", index + 1) })
                    .collect();
                sink.line(&record.join("\n"));
            }
        }
        sink.flush_stdout();
    }
    for (index, total) in totals.iter().enumerate() {
        sink.comment(&format!("# r{} {total} results", index + 1));
    }
    let io_result = sink.finish();
    errors.sort();
    errors.dedup();
    for error in &errors {
        io.note(format_args!("Warning: {error}"));
    }
    if errors.is_empty() {
        for (index, rule) in asked.rules.iter().enumerate().filter(|(index, _)| totals[*index] == 0) {
            for hint in engine.no_results_hints(rule, cancel) {
                io.note(format_args!("hint: r{}: {hint}", index + 1));
            }
        }
    }
    io_result?;
    let unsearched = unreadable + errors.len();
    if unsearched == 0 {
        return Ok(EXIT_OK);
    }
    io.note(format_args!("Warning: {unsearched} ABC entr{} could not be searched", if unsearched == 1 { "y" } else { "ies" }));
    Ok(EXIT_PARTIAL)
}
