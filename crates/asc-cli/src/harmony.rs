//! HarmonyOS programs (`.hap` / `.hsp` / `.app` / `.abc`) behind the commands
//! of the DEX side: `listclass`, `getclass` / `disassemble`, `getmanifest`,
//! `manifest-summary`, `resources`, `xml` (the text files of a package),
//! `findrefs` (string, prop, global, import, method, number, call, all),
//! `callgraph` and `hierarchy`.
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
    Manifest, NameFilter, Pattern, Query, ResourceField, ResourceTables,
};
use asc_mcp::harmony::{function_roots, leaf_roots, no_callers_hint, no_class_hint, no_leaf_hint, CallerFilter, TreeText};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// The `findrefs` kinds that work on a HarmonyOS program.
const SEARCHES: &str = "string, prop, global, import, method, number, call, all";
/// What `callgraph` takes on a HarmonyOS program.
const WALKS: &str =
    "[RECORD] FUNCTION or --to call:PATTERN, --from method:NAME, --callees, --depth, --max-nodes, --no-defines, --unresolved, --entry";

/// What a `findrefs` kind or option the engine does not have says.
fn unsupported_search(what: &str) -> String {
    format!("findrefs {what} is not supported for HarmonyOS programs yet (supported: findrefs {SEARCHES})")
}

/// As [`unsupported_search`], for a `callgraph` option.
fn unsupported_walk(what: &str) -> String {
    format!("callgraph {what} is not supported for HarmonyOS programs yet (supported: callgraph {WALKS})")
}

fn dex_only(flag: &str) -> String {
    format!("{flag} is DEX-only")
}

/// Run a one-shot command on the HarmonyOS program it names: the exit status.
pub(crate) fn run(io: &mut Io<'_>, common: &Common, command: Command, t_start: Instant) -> Result<u8, String> {
    io.window = common.window();
    io.spill = common.spill();
    let code = match command {
        Command::Listclass { prefix, all, output, apk_path } => {
            let engine = open(io, common, &apk_path)?;
            listclass(io, &engine, prefix, all, output.as_ref())?;
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
        Command::Findrefs { apk_path, context, context_method, access, find } => {
            if context.is_some() || context_method {
                return Err(unsupported_search("--context"));
            }
            match search(io, find, access)? {
                Search::Refs { query, output } => {
                    let engine = open(io, common, &apk_path)?;
                    findrefs(io, &engine, &query, output.as_ref())?
                }
                Search::Requests { pattern, output } => {
                    let engine = open(io, common, &apk_path)?;
                    module_requests(io, &engine, &pattern, output.as_ref())?;
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
            if !unless.is_empty() {
                return Err(unsupported_walk("--unless"));
            }
            if unresolved && !callees {
                return Err("--unresolved lists callees: add --callees".into());
            }
            let from = from.map(|rule| CallerFilter::parse(&rule, "--from")).transpose()?;
            if from.is_some() && callees {
                return Err("--from keeps caller paths: leave out --callees".into());
            }
            let target = CallTarget { class, method, to, entry };
            let direction = if callees { Direction::Callees } else { Direction::Callers };
            let query =
                CallQuery { depth, max_nodes, defines: !no_defines, unresolved, ..CallQuery::new(target.roots(direction)?, direction) };
            let engine = open(io, common, &apk_path)?;
            callgraph(io, &engine, &query, from.as_ref(), target.to.as_deref(), output.as_ref())?
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
/// packages without code), as the DEX side reports its program notes.
fn open(io: &mut Io<'_>, common: &Common, path: &Path) -> Result<Arc<Engine>, String> {
    let engine = io.harmony(common, path).map_err(|e| e.to_string())?;
    for note in engine.notes() {
        io.note(format_args!("# warning: {note}"));
    }
    Ok(engine)
}

/// One record per line; a program of several ABC entries also names the entry.
fn listclass(io: &mut Io<'_>, engine: &Engine, prefix: Option<String>, all: bool, output: Option<&PathBuf>) -> Result<(), String> {
    let options = ListOptions { filter: prefix.map(NameFilter::Prefix), all };
    let records = engine.list_classes(&options).map_err(|e| e.to_string())?;
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
            text.push_str(&format!("# {}/{}\n", found.package, found.document));
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
}

/// A name pattern: a regex, or with `--literal` / `--exact` plain text.
fn pattern(text: &str, literal: bool, exact: bool) -> Result<Pattern, String> {
    match (literal, exact) {
        (_, true) => Ok(Pattern::exact(text)),
        (true, false) => Ok(Pattern::contains(text)),
        (false, false) => Pattern::regex(text).map_err(|e| e.to_string()),
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

/// One condition of `findrefs all`.
fn condition(io: &Io<'_>, spec: &str) -> Result<Query, String> {
    let kind = spec.split_once(':').map_or(spec, |(kind, _)| kind);
    match kind {
        // Parsed as the DEX side parses them: one syntax for the text conditions of both.
        "string" | "literal" => match io.condition(spec)? {
            asc_findrefs::Query::String(pattern) => Query::string_regex(&pattern).map_err(|e| e.to_string()),
            asc_findrefs::Query::StringLiteral(text) => Ok(Query::string_literal(text)),
            _ => Err(unsupported_search(spec)),
        },
        _ if Query::KINDS.contains(&kind) => Query::condition(spec).map_err(|e| e.to_string()),
        _ => Err(format!(
            "findrefs {kind}: is not supported for HarmonyOS programs yet (supported: {})",
            Query::KINDS.map(|kind| format!("{kind}:")).join(", ")
        )),
    }
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
        Find::Prop { output, literal, exact, name } => return refs(Query::Prop { name: pattern(&name, literal, exact)?, access }, output),
        Find::Global { output, literal, exact, name } => {
            return refs(Query::global(pattern(&name, literal, exact)?, access).map_err(|e| e.to_string())?, output);
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
                Query::method(&spec, |name| pattern(name, false, exact).map_err(EngineError::Query)).map_err(|e| e.to_string())?,
                output,
            );
        }
        Find::Number { output, value } => return refs(Query::Number(value.parse().map_err(|e: EngineError| e.to_string())?), output),
        Find::Call { output, literal, path } => return refs(Query::Call(pattern(&path, literal, false)?), output),
        Find::All { output, none, conditions } => {
            if !none.is_empty() || conditions.iter().any(|condition| condition.starts_with('!')) {
                return Err(unsupported_search("all with excluded conditions"));
            }
            let mut queries = conditions.iter().map(|spec| condition(io, spec)).collect::<Result<Vec<_>, _>>()?;
            // One condition is that query itself, as on the DEX side.
            let query = if queries.len() == 1 { queries.remove(0) } else { Query::All(queries) };
            return refs(query, output);
        }
        Find::Type { .. } => "type",
        Find::Extends { .. } => "extends",
        Find::Impl { .. } => "impl",
        Find::Field { .. } => "field",
        Find::Rules { .. } => "rules",
    };
    Err(unsupported_search(kind))
}

/// `findrefs import --requests`: one line per distinct module request.
fn module_requests(io: &mut Io<'_>, engine: &Engine, pattern: &Pattern, output: Option<&PathBuf>) -> Result<(), String> {
    let requests = engine.module_requests(Some(pattern)).map_err(|e| e.to_string())?;
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
    to: Option<String>,
    entry: Option<String>,
}

impl CallTarget {
    /// The roots of a walk in `direction`: the function `RECORD FUNCTION`
    /// names, or one argument as result rows print it (`RECORD->FUNCTION`,
    /// `RECORD->FUNCTION+0xPC`) or a function name alone; or the callee
    /// paths `--to call:PATTERN` matches.
    fn roots(&self, direction: Direction) -> Result<CallRoots, String> {
        let entry = self.entry.as_deref();
        match (&self.class, &self.method, &self.to) {
            (None, _, None) => {
                Err("callgraph needs a target: [RECORD] FUNCTION (or RECORD->FUNCTION, as result rows print it) or --to call:PATTERN"
                    .into())
            }
            (Some(_), _, Some(_)) => Err("give the target as [RECORD] FUNCTION or as --to call:PATTERN, not both".into()),
            (None, _, Some(_)) if entry.is_some() => Err("--entry picks the root function: it does not go with --to".into()),
            (None, _, Some(_)) if direction == Direction::Callees => {
                Err("--to call:PATTERN walks the callers of a callee path: leave out --callees".into())
            }
            (None, _, Some(to)) => leaf_roots(to, "--to"),
            (Some(record), Some(function), None) => Ok(function_roots(Some(record), function, entry)),
            (Some(spec), None, None) => Ok(function_roots(None, spec, entry)),
        }
    }
}

/// ABC entries no query reads (encrypted, damaged): named when the program opened.
fn unreadable_entries(engine: &Engine) -> usize {
    engine.entries().filter(|entry| entry.status != EntryStatus::Readable).count()
}

/// The tree of `query`, with `from` the caller paths it keeps: the exit
/// status, [`EXIT_PARTIAL`] when part of the program could not be walked.
/// `to`: the `--to` rule, for the hint of a walk that found no callee path.
fn callgraph(
    io: &mut Io<'_>,
    engine: &Engine,
    query: &CallQuery,
    from: Option<&CallerFilter>,
    to: Option<&str>,
    output: Option<&PathBuf>,
) -> Result<u8, String> {
    let mut tree = engine.call_graph(query, io.cancel).map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if several_entries_define(candidates) => {
            format!("{e}\n(name the entry, the first column, with --entry)")
        }
        EngineError::NotFound { what: "function", .. } => format!("{e} (`findrefs method NAME` lists the functions a name defines)"),
        _ => e.to_string(),
    })?;
    // Said on stderr when the program opened.
    tree.notes.clear();
    let shown = TreeText::of(&tree, engine.has_several_entries(), from);
    io.emit_tree(output, &shown.lines, &shown.footer)?;
    if let (Some(to), true) = (to, tree.rows.is_empty()) {
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

/// One row per reference, entry by entry in program order: the exit status,
/// [`EXIT_PARTIAL`] when part of the program could not be searched.
fn findrefs(io: &mut Io<'_>, engine: &Engine, query: &Query, output: Option<&PathBuf>) -> Result<u8, String> {
    let cancel = io.cancel;
    let mut sink = io.sink(output, true)?;
    let mut errors = Vec::new();
    let summary = engine
        .find_refs(query, cancel, &mut |batch| {
            for row in &batch.rows {
                sink.line(&row.line(&batch.entry_name));
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
    }
    io_result?;
    // Entries left out whole (encrypted, damaged) were named when the program opened.
    let unsearched = unreadable_entries(engine) + errors.len();
    if unsearched == 0 {
        return Ok(EXIT_OK);
    }
    io.note(format_args!("Warning: {unsearched} ABC entr{} could not be searched", if unsearched == 1 { "y" } else { "ies" }));
    Ok(EXIT_PARTIAL)
}
