//! Exercise the HarmonyOS call graph from the command line, ahead of its
//! CLI integration, and check it against itself:
//!
//! ```text
//! arkcg callers|callees <path> <ROOT> [--leaf] [--depth N] [--max-nodes N] [--no-defines] [--unresolved]
//! arkcg edges  <path>              every edge, tab separated
//! arkcg build  <path>              build the whole graph: time and size
//! arkcg forms  <path>              module request forms and how many resolve
//! arkcg check  <path> [--sample N] [--seed S]
//! ```
//!
//! `ROOT` is `FUNCTION` or `RECORD->FUNCTION`; with `--leaf` a regex over
//! callee paths (`^import:@ohos:net\.http`).
//!
//! `check` takes every function (or `--sample N` of them, chosen with a
//! fixed-seed generator) and verifies that the two directions agree: each
//! callee of `B` lists `B` among its callers, and each caller of `A` lists
//! `A` among its callees. The callers side of each test runs on a fresh
//! engine without the whole graph loaded, so it also tests that the records
//! a callers walk looks at are enough.
//!
//! `--threads N` and `--time` work with every command.

use std::collections::HashSet;
use std::error::Error;
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use asc_ark_engine::{CallNode, CallQuery, CallRoots, CallTree, Direction, Engine, Pattern};

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

fn location(node: &CallNode) -> String {
    match node {
        CallNode::Function { record, function, .. } => format!("{record}->{function}"),
        CallNode::Leaf { path, external } => format!("{}:{path}", if *external { "external" } else { "unresolved" }),
    }
}

/// The nodes one level from the root of `tree`.
fn level_one(tree: &CallTree) -> HashSet<CallNode> {
    tree.rows.iter().filter(|row| row.depth == 1).map(|row| row.node.clone()).collect()
}

fn root_of(node: &CallNode) -> Option<CallRoots> {
    match node {
        CallNode::Function { entry, record, function, .. } => {
            Some(CallRoots::Function { record: Some(record.clone()), function: function.clone(), entry: Some(entry.clone()) })
        }
        CallNode::Leaf { .. } => None,
    }
}

fn neighbors(engine: &Engine, node: &CallNode, direction: Direction) -> Result<HashSet<CallNode>, Box<dyn Error>> {
    let Some(roots) = root_of(node) else { return Ok(HashSet::new()) };
    let query = CallQuery { depth: 1, max_nodes: usize::MAX, unresolved: false, ..CallQuery::new(roots, direction) };
    Ok(level_one(&engine.call_graph(&query, &AtomicBool::new(false))?))
}

/// xorshift64*: a fixed sequence for a fixed seed.
fn next(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

fn check(path: &str, threads: Option<usize>, sample: Option<usize>, seed: u64) -> Result<usize, Box<dyn Error>> {
    let open = || -> Result<Engine, Box<dyn Error>> {
        let engine = Engine::open(path)?;
        Ok(match threads {
            Some(threads) => engine.with_threads(threads),
            None => engine,
        })
    };
    let full = open()?;
    let mut functions: Vec<CallNode> = Vec::new();
    let mut seen = HashSet::new();
    full.call_edges(&AtomicBool::new(false), &mut |edge| {
        if seen.insert(edge.from.clone()) {
            functions.push(edge.from);
        }
    })?;
    if let Some(sample) = sample {
        let mut state = seed.max(1);
        let mut picked = Vec::new();
        while picked.len() < sample.min(functions.len()) {
            let index = (next(&mut state) % functions.len() as u64) as usize;
            picked.push(functions.swap_remove(index));
        }
        functions = picked;
    }
    let mut failures = 0;
    let mut pairs = 0;
    for function in &functions {
        // The callers walks start cold: only the records the walk itself picks are loaded.
        let cold = open()?;
        for callee in neighbors(&full, function, Direction::Callees)? {
            if matches!(callee, CallNode::Leaf { .. }) {
                continue;
            }
            pairs += 1;
            if !neighbors(&cold, &callee, Direction::Callers)?.contains(function) {
                failures += 1;
                println!("MISSING caller: {} not among the callers of {}", location(function), location(&callee));
            }
        }
        for caller in neighbors(&cold, function, Direction::Callers)? {
            pairs += 1;
            if !neighbors(&full, &caller, Direction::Callees)?.contains(function) {
                failures += 1;
                println!("MISSING callee: {} not among the callees of {}", location(function), location(&caller));
            }
        }
    }
    println!("{} functions checked, {pairs} caller/callee pairs, {failures} inconsistencies", functions.len());
    Ok(failures)
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
    let depth = take_value(&mut args, "--depth").map(|n| n.parse::<usize>()).transpose()?;
    let max_nodes = take_value(&mut args, "--max-nodes").map(|n| n.parse::<usize>()).transpose()?;
    let sample = take_value(&mut args, "--sample").map(|n| n.parse::<usize>()).transpose()?;
    let seed = take_value(&mut args, "--seed").map(|n| n.parse::<u64>()).transpose()?.unwrap_or(1);
    let (leaf, no_defines, unresolved) =
        (take_flag(&mut args, "--leaf"), take_flag(&mut args, "--no-defines"), take_flag(&mut args, "--unresolved"));
    let [command, path, rest @ ..] = &args[..] else {
        return Err("usage: arkcg callers|callees|edges|build|forms|check <path> ...".into());
    };
    if command == "check" {
        return match check(path, threads, sample, seed)? {
            0 => Ok(()),
            failures => Err(format!("{failures} inconsistencies").into()),
        };
    }
    let started = Instant::now();
    let mut engine = Engine::open(path)?;
    if let Some(threads) = threads {
        engine = engine.with_threads(threads);
    }
    let opened = started.elapsed();
    let cancel = AtomicBool::new(false);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let queried = Instant::now();
    match (command.as_str(), rest) {
        ("callers" | "callees", [root]) => {
            let direction = if command == "callers" { Direction::Callers } else { Direction::Callees };
            let roots = if leaf { CallRoots::Leaf(Pattern::regex(root)?) } else { CallRoots::function(root) };
            let mut query = CallQuery::new(roots, direction);
            query.depth = depth.unwrap_or(query.depth);
            query.max_nodes = max_nodes.unwrap_or(query.max_nodes);
            query.defines = !no_defines;
            query.unresolved = unresolved;
            let tree = engine.call_graph(&query, &cancel)?;
            for line in tree.lines(engine.has_several_entries()) {
                writeln!(out, "{line}")?;
            }
            writeln!(out, "{}", tree.footer())?;
        }
        ("edges", []) => {
            let mut failed = None;
            engine.call_edges(&cancel, &mut |edge| {
                let written = writeln!(
                    out,
                    "{}\t{:#x}\t{:?}\t{}\t{}",
                    location(&edge.from),
                    edge.pc,
                    edge.kind,
                    location(&edge.to),
                    edge.via.unwrap_or_default()
                );
                failed = failed.take().or(written.err());
            })?;
            if let Some(error) = failed {
                return Err(error.into());
            }
        }
        ("build", []) => {
            let size = engine.build_call_graph(&cancel)?;
            writeln!(out, "{size:?}")?;
        }
        ("forms", []) => {
            for (form, count) in engine.request_forms(&cancel)? {
                writeln!(out, "{:<26} {:>7} requests, {:>7} name a record of the program", form.label(), count.requests, count.resolved)?;
            }
        }
        _ => return Err(format!("bad arguments for {command}").into()),
    }
    out.flush()?;
    if timing {
        // Linux only; elsewhere the peak is not printed.
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let peak = status.lines().find_map(|line| line.strip_prefix("VmHWM:")).map_or("?", str::trim);
        eprintln!("# open {opened:?}, query {:?}, threads {}, peak rss {peak}", queried.elapsed(), engine.threads());
    }
    Ok(())
}
