//! Exercise the HarmonyOS engine from the command line, ahead of its CLI
//! integration:
//!
//! ```text
//! arkq info      <path>
//! arkq listclass <path> [--all] [--prefix P | --contains S | --regex R]
//! arkq getclass  <path> <record> [function] [--entry E]
//! arkq findrefs  <path> <regex> [--literal]
//! arkq findrefs  <path> KIND:VALUE... [--access read|write|define|call] [--decl] [--count] [--offsets [--paths]]
//! arkq requests  <path> [regex]
//! ```
//!
//! Several conditions are a conjunction. `--count` prints no rows (for
//! timing); `--offsets` prints `0xOFFSET<TAB>text` with the absolute file
//! offset of each instruction, the form an `ark_disasm` listing can be
//! compared with; `--paths` puts what matched (a call's callee path) in
//! place of the text.
//!
//! `--threads N` and `--time` (timings and peak RSS on stderr) work with every
//! command.

use std::error::Error;
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use std::collections::HashMap;

use asc_ark_engine::{Access, ClassQuery, Engine, EntryStatus, Format, ListOptions, NameFilter, Pattern, Query, RefRow, RefSite};

/// Remove `flag` from `args`; whether it was there.
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|arg| arg != flag);
    args.len() != before
}

/// Remove `flag VALUE` from `args`.
fn take_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let at = args.iter().position(|arg| arg == flag)?;
    if at + 1 >= args.len() {
        return None;
    }
    args.remove(at);
    Some(args.remove(at))
}

/// The query of `findrefs`: a string search, one condition, or several as a conjunction.
fn query_of(specs: &[String], literal: bool, access: Option<Access>, declarations_only: bool) -> Result<Query, Box<dyn Error>> {
    let is_condition = |spec: &str| Query::KINDS.iter().any(|kind| spec.strip_prefix(kind).is_some_and(|rest| rest.starts_with(':')));
    let mut queries = Vec::new();
    for spec in specs {
        let query = match spec.as_str() {
            spec if is_condition(spec) => match Query::condition(spec)? {
                Query::Prop { name, .. } => Query::Prop { name, access },
                Query::Global { name, .. } => Query::global(name, access)?,
                Query::Import { request, name, .. } => Query::Import { request, name, declarations_only },
                query => query,
            },
            text if literal => Query::string_literal(text),
            pattern => Query::string_regex(pattern)?,
        };
        queries.push(query);
    }
    Ok(if queries.len() == 1 { queries.remove(0) } else { Query::All(queries) })
}

/// Absolute file offsets of the instructions of result rows.
#[derive(Default)]
struct Offsets {
    /// Per `(entry, record)`: where the code of each function starts.
    code_starts: HashMap<(String, String), HashMap<String, u32>>,
}

impl Offsets {
    fn of(&mut self, engine: &Engine, entry: &str, row: &RefRow) -> Option<u32> {
        let RefSite::Code { function, pc, .. } = &row.site else { return None };
        let starts = self.code_starts.entry((entry.to_owned(), row.record.clone())).or_insert_with(|| {
            let mut starts = HashMap::new();
            let class =
                engine.abc(entry).and_then(|abc| abc.find_record(row.record.as_bytes()).ok().flatten()).and_then(|class| class.local());
            for method in class.and_then(|class| class.methods().ok()).into_iter().flatten().map_while(|method| method.ok()) {
                if let (Ok(name), Ok(Some(code))) = (method.name(), method.code()) {
                    starts.entry(name.to_str().into_owned()).or_insert(code.instructions_off());
                }
            }
            starts
        });
        starts.get(function).map(|start| start + pc)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let timing = take_flag(&mut args, "--time");
    let threads = take_value(&mut args, "--threads").map(|n| n.parse::<usize>()).transpose()?;
    let all = take_flag(&mut args, "--all");
    let literal = take_flag(&mut args, "--literal");
    let (count_only, with_offsets, declarations_only) =
        (take_flag(&mut args, "--count"), take_flag(&mut args, "--offsets"), take_flag(&mut args, "--decl"));
    let paths = take_flag(&mut args, "--paths");
    let access = match take_value(&mut args, "--access").as_deref() {
        None => None,
        Some(label) => Some(Access::ALL.into_iter().find(|access| access.label() == label).ok_or("--access read|write|define|call")?),
    };
    let entry = take_value(&mut args, "--entry");
    let filter = if let Some(prefix) = take_value(&mut args, "--prefix") {
        Some(NameFilter::Prefix(prefix))
    } else if let Some(part) = take_value(&mut args, "--contains") {
        Some(NameFilter::Contains(part))
    } else {
        take_value(&mut args, "--regex").map(|pattern| regex::Regex::new(&pattern).map(NameFilter::Regex)).transpose()?
    };
    let [command, path, rest @ ..] = &args[..] else {
        return Err("usage: arkq info|listclass|getclass|findrefs <path> ...".into());
    };

    let started = Instant::now();
    let mut engine = Engine::open(path)?;
    if let Some(threads) = threads {
        engine = engine.with_threads(threads);
    }
    let opened = started.elapsed();
    for note in engine.notes() {
        eprintln!("# {note}");
    }
    let several = engine.has_several_entries();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let queried = Instant::now();
    let rows = match (command.as_str(), rest) {
        ("info", []) => {
            writeln!(out, "format: {:?}", Format::detect(path.as_ref()))?;
            for info in engine.entries() {
                let version = info.version.map_or_else(|| "?".to_owned(), |version| version.to_string());
                let status = match &info.status {
                    EntryStatus::Readable => "readable".to_owned(),
                    EntryStatus::Encrypted => "encrypted".to_owned(),
                    EntryStatus::Unreadable(reason) => format!("unreadable: {reason}"),
                };
                writeln!(out, "{} | version={version} size={} | {status}", info.name, info.size)?;
            }
            engine.entries().count()
        }
        ("listclass", []) => {
            let records = engine.list_classes(&ListOptions { filter, all, entry: None })?;
            for record in &records {
                writeln!(out, "{}", record.line(several))?;
            }
            records.len()
        }
        ("getclass", [record, function @ ..]) => {
            let query = ClassQuery { record, function: function.first().map(String::as_str), entry: entry.as_deref() };
            let source = engine.get_class(&query)?;
            write!(out, "{}", source.text)?;
            source.text.lines().count()
        }
        ("requests", pattern) => {
            let pattern = pattern.first().map(|pattern| Pattern::regex(pattern)).transpose()?;
            let requests = engine.module_requests(pattern.as_ref())?;
            for request in &requests {
                writeln!(out, "{}", request.line(several))?;
            }
            requests.len()
        }
        ("findrefs", specs @ [_, ..]) => {
            let query = query_of(specs, literal, access, declarations_only)?;
            let mut failed = None;
            let mut offsets = Offsets::default();
            let summary = engine.find_refs(&query, &AtomicBool::new(false), &mut |batch| {
                for row in batch.rows.iter().filter(|_| !count_only) {
                    let written = match offsets.of(&engine, &batch.entry_name, row).filter(|_| with_offsets) {
                        Some(offset) if paths => writeln!(out, "{offset:#x}\t{}", row.matched.join("\t")),
                        Some(offset) => writeln!(out, "{offset:#x}\t{}", row.text),
                        None => writeln!(out, "{}", row.line(&batch.entry_name)),
                    };
                    failed = failed.take().or(written.err());
                }
                if let Some(error) = &batch.error {
                    eprintln!("# {}: {error}", batch.entry_name);
                }
            })?;
            if let Some(error) = failed {
                return Err(error.into());
            }
            summary.total_results
        }
        _ => return Err(format!("bad arguments for {command}").into()),
    };
    out.flush()?;
    if timing {
        // Linux only; elsewhere the peak is not printed.
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let peak = status.lines().find_map(|line| line.strip_prefix("VmHWM:")).map_or("?", str::trim);
        eprintln!("# open {opened:?}, query {:?}, rows {rows}, threads {}, peak rss {peak}", queried.elapsed(), engine.threads());
    }
    Ok(())
}
