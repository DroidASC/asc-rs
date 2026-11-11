//! Exercise the HarmonyOS class hierarchy from the command line and
//! measure it:
//!
//! ```text
//! arkhier stats <path>     class definitions by how their parent was found, and the time
//! arkhier defs  <path>     every class definition, tab separated:
//!                          record, constructor, definer, pc, kind, parent
//! arkhier tree  <path> <CLASS> [--supers] [--depth N] [--max-nodes N] [--method NAME]
//! ```
//!
//! `--threads N` works with every command.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use asc_ark_engine::{ClassDefinition, ClassNode, Engine, HierarchyQuery, Lineage, ParentKind};

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|arg| arg != flag);
    args.len() != before
}

fn take_value(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let at = args.iter().position(|arg| arg == flag)?;
    if at + 1 >= args.len() {
        return None;
    }
    args.remove(at);
    Some(args.remove(at))
}

fn location(node: &ClassNode) -> String {
    match node {
        ClassNode::Class { record, function, .. } => format!("{record}->{function}"),
        ClassNode::Leaf { path, .. } => path.clone(),
    }
}

fn definitions(engine: &Engine) -> Result<(Vec<ClassDefinition>, usize), Box<dyn Error>> {
    let mut out = Vec::new();
    let records = engine.class_definitions(&AtomicBool::new(false), &mut |definition| out.push(definition))?;
    Ok((out, records))
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let threads = take_value(&mut args, "--threads").map(|n| n.parse::<usize>()).transpose()?;
    let supers = take_flag(&mut args, "--supers");
    let depth = take_value(&mut args, "--depth").map(|n| n.parse::<usize>()).transpose()?;
    let max_nodes = take_value(&mut args, "--max-nodes").map(|n| n.parse::<usize>()).transpose()?;
    let method = take_value(&mut args, "--method");
    let (Some(command), Some(path)) = (args.first().cloned(), args.get(1).cloned()) else {
        return Err("usage: arkhier stats|defs|tree <path> [CLASS] (see the file header)".into());
    };
    let opened = Instant::now();
    let mut engine = Engine::open(&path)?;
    if let Some(threads) = threads {
        engine = engine.with_threads(threads);
    }
    let open_us = opened.elapsed().as_micros();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    match command.as_str() {
        "stats" => {
            let started = Instant::now();
            let (all, records) = definitions(&engine)?;
            let first_us = started.elapsed().as_micros();
            let again = Instant::now();
            definitions(&engine)?;
            let mut kinds: BTreeMap<ParentKind, usize> = BTreeMap::new();
            let mut sendable = 0;
            let mut odd_literals = 0;
            let mut reassigned = 0;
            let mut unresolved: BTreeMap<String, usize> = BTreeMap::new();
            let mut external: BTreeMap<String, usize> = BTreeMap::new();
            for definition in &all {
                *kinds.entry(definition.kind).or_default() += 1;
                sendable += usize::from(definition.sendable);
                odd_literals += usize::from(definition.methods.is_none());
                reassigned += usize::from(definition.reassigned);
                let table = match definition.kind {
                    ParentKind::Unresolved => &mut unresolved,
                    ParentKind::External => &mut external,
                    _ => continue,
                };
                *table.entry(definition.parent.as_ref().map(location).unwrap_or_default()).or_default() += 1;
            }
            writeln!(
                out,
                "records {records}, class definitions {} (sendable {sendable}, literal not understood {odd_literals})",
                all.len()
            )?;
            for kind in ParentKind::ALL {
                let count = kinds.get(&kind).copied().unwrap_or(0);
                writeln!(out, "  {:<13} {count:>6}  {:5.1}%", kind.label(), 100.0 * count as f64 / all.len().max(1) as f64)?;
            }
            writeln!(out, "  through a reassigned binding: {reassigned}")?;
            for (title, table) in [("unresolved", &unresolved), ("external", &external)] {
                let mut top: Vec<_> = table.iter().collect();
                top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                writeln!(out, "{title} parents: {} distinct", top.len())?;
                for (path, count) in top.into_iter().take(25) {
                    writeln!(out, "  {count:>5}  {path}")?;
                }
            }
            let held = engine.memory_use();
            writeln!(
                out,
                "open {open_us} us, first pass {first_us} us, second pass {} us, {} threads, analyses {} bytes",
                again.elapsed().as_micros(),
                engine.threads(),
                held.analyses
            )?;
        }
        "defs" => {
            for definition in definitions(&engine)?.0 {
                let ClassNode::Class { record, function, .. } = &definition.class else { continue };
                let parent = definition.parent.as_ref().map(location).unwrap_or_default();
                let kind = definition.kind.label();
                let flag = if definition.reassigned { " reassigned" } else { "" };
                writeln!(out, "{record}\t{function}\t{}\t{:#x}\t{kind}{flag}\t{parent}", definition.definer, definition.pc)?;
            }
        }
        "tree" => {
            let class = args.get(2).ok_or("tree needs a CLASS")?;
            let direction = if supers { Lineage::Supers } else { Lineage::Subclasses };
            let mut query = HierarchyQuery::new(class.as_str(), direction).method(method);
            query.depth = depth.unwrap_or(query.depth);
            query.max_nodes = max_nodes.unwrap_or(query.max_nodes);
            let started = Instant::now();
            let tree = engine.hierarchy(&query, &AtomicBool::new(false))?;
            let walk_us = started.elapsed().as_micros();
            let (lines, footer) = tree.text(engine.has_several_entries());
            for line in lines {
                writeln!(out, "{line}")?;
            }
            writeln!(out, "{footer}")?;
            writeln!(out, "# open {open_us} us, walk {walk_us} us")?;
        }
        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("arkhier: {error}");
            ExitCode::FAILURE
        }
    }
}
