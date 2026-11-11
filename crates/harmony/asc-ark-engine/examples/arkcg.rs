//! Exercise the HarmonyOS call graph from the command line, ahead of its
//! CLI integration, and check it against itself:
//!
//! ```text
//! arkcg callers|callees <path> <ROOT> [--leaf] [--depth N] [--max-nodes N] [--no-defines] [--unresolved]
//!                                  [--max-subclasses N]
//! arkcg edges  <path>              every edge, tab separated: from, pc, kind, to, the callee
//!                                  path of an edge through an import, the ABC entry of `to`
//! arkcg build  <path>              build the whole graph: time and size
//! arkcg forms  <path>              module request forms and how many resolve
//! arkcg census <path>              edges per kind and target, leaf shares, cold / warm time, memory
//! arkcg check  <path> [--sample N] [--seed S] [--kind KIND]
//! arkcg worst  <path> [--sample N] [--max-subclasses N]
//!                                  the callers of one instance method of every class that has
//!                                  subclasses (or of the N with most direct ones), each walk on
//!                                  a fresh engine: the slowest walks and the largest scans
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
//! With `--kind KIND` (`super`, `instance`, `inherited`, `reassigned` …,
//! the flag rows carry) the functions are the ones with a call site of that
//! kind.
//!
//! `--threads N` and `--time` work with every command.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use asc_ark_engine::{CallNode, CallQuery, CallRoots, CallTree, ClassNode, Direction, Engine, Pattern};

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
        CallNode::Leaf { path, kind } => format!("{}:{path}", kind.label()),
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

fn check(path: &str, threads: Option<usize>, sample: Option<usize>, seed: u64, kind: Option<&str>) -> Result<usize, Box<dyn Error>> {
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
        if kind.is_none_or(|kind| edge.kind.label() == Some(kind)) && seen.insert(edge.from.clone()) {
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

/// One callers walk of [`worst`].
struct Walk {
    micros: u128,
    records: usize,
    rows: usize,
    subclasses: usize,
    footer: String,
    root: String,
}

/// Walk the callers of one instance method of each class that is the parent
/// of another: where the walk has to look through subclasses.
fn worst(path: &str, threads: Option<usize>, sample: Option<usize>, max_subclasses: Option<usize>) -> Result<(), Box<dyn Error>> {
    let open = || -> Result<Engine, Box<dyn Error>> {
        let engine = Engine::open(path)?;
        Ok(match threads {
            Some(threads) => engine.with_threads(threads),
            None => engine,
        })
    };
    let cancel = AtomicBool::new(false);
    let full = open()?;
    // Direct subclasses per parent class of the program: (entry, record, constructor).
    let mut parents: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    full.class_definitions(&cancel, &mut |definition| {
        if let Some(ClassNode::Class { entry, record, function, .. }) = definition.parent {
            *parents.entry((entry, record, function)).or_default() += 1;
        }
    })?;
    // The functions of each record, by name.
    let mut functions: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut seen = HashSet::new();
    full.call_edges(&cancel, &mut |edge| {
        if let CallNode::Function { entry, record, function, .. } = &edge.from {
            if seen.insert(edge.from.clone()) {
                functions.entry((entry.clone(), record.clone())).or_default().push(function.clone());
            }
        }
    })?;
    drop(full);
    let mut classes: Vec<((String, String, String), usize)> = parents.into_iter().collect();
    classes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    classes.truncate(sample.unwrap_or(usize::MAX));
    let mut walks = Vec::new();
    for ((entry, record, ctor), subclasses) in classes {
        // `#~@0=#Name` is the constructor of the class whose instance methods are `#~@0>#name`.
        let Some(scope) = ctor.split_once('=').map(|(scope, _)| format!("{scope}>#")) else { continue };
        let of_record = functions.get(&(entry.clone(), record.clone()));
        let Some(method) = of_record.and_then(|names| names.iter().find(|name| name.starts_with(&scope))) else { continue };
        let roots = CallRoots::Function { record: Some(record.clone()), function: method.clone(), entry: Some(entry) };
        let mut query = CallQuery { depth: 1, max_nodes: usize::MAX, ..CallQuery::new(roots, Direction::Callers) };
        query.max_subclasses = max_subclasses.unwrap_or(query.max_subclasses);
        let cold = open()?;
        let started = Instant::now();
        let tree = cold.call_graph(&query, &cancel)?;
        walks.push(Walk {
            micros: started.elapsed().as_micros(),
            records: tree.records_scanned,
            rows: tree.rows.len(),
            subclasses,
            footer: tree.footer().lines().skip(1).collect::<Vec<_>>().join(" "),
            root: format!("{record}->{method}"),
        });
    }
    let print = |title: &str, walks: &[Walk]| {
        println!("{title}");
        for walk in walks.iter().take(8) {
            println!(
                "  {:>8} us {:>6} records {:>5} rows {:>4} direct subclasses  {} {}",
                walk.micros, walk.records, walk.rows, walk.subclasses, walk.root, walk.footer
            );
        }
    };
    let total: u128 = walks.iter().map(|walk| walk.micros).sum();
    println!("{} walks, {} us in all, {} us on average", walks.len(), total, total / walks.len().max(1) as u128);
    walks.sort_by_key(|walk| std::cmp::Reverse(walk.micros));
    print("slowest:", &walks);
    walks.sort_by_key(|walk| std::cmp::Reverse(walk.records));
    print("most records scanned:", &walks);
    Ok(())
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
    let kind = take_value(&mut args, "--kind");
    let max_subclasses = take_value(&mut args, "--max-subclasses").map(|n| n.parse::<usize>()).transpose()?;
    let (leaf, no_defines, unresolved) =
        (take_flag(&mut args, "--leaf"), take_flag(&mut args, "--no-defines"), take_flag(&mut args, "--unresolved"));
    let [command, path, rest @ ..] = &args[..] else {
        return Err("usage: arkcg callers|callees|edges|build|forms|census|check|worst <path> ...".into());
    };
    if command == "worst" {
        return worst(path, threads, sample, max_subclasses);
    }
    if command == "check" {
        return match check(path, threads, sample, seed, kind.as_deref())? {
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
            query.max_subclasses = max_subclasses.unwrap_or(query.max_subclasses);
            let tree = engine.call_graph(&query, &cancel)?;
            for line in tree.lines(engine.has_several_entries()) {
                writeln!(out, "{line}")?;
            }
            writeln!(out, "{}", tree.footer())?;
        }
        ("edges", []) => {
            let mut failed = None;
            engine.call_edges(&cancel, &mut |edge| {
                let entry = match &edge.to {
                    CallNode::Function { entry, .. } => entry.as_str(),
                    CallNode::Leaf { .. } => "",
                };
                let written = writeln!(
                    out,
                    "{}\t{:#x}\t{:?}\t{}\t{}\t{entry}",
                    location(&edge.from),
                    edge.pc,
                    edge.kind,
                    location(&edge.to),
                    edge.via.as_deref().unwrap_or_default()
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
        ("census", []) => {
            let cold = Instant::now();
            let size = engine.build_call_graph(&cancel)?;
            let cold = cold.elapsed();
            let warm = Instant::now();
            let mut census: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
            engine.call_edges(&cancel, &mut |edge| {
                let to = match (&edge.to, &edge.via) {
                    (CallNode::Function { .. }, Some(_)) => "function through an import",
                    (CallNode::Function { .. }, None) => "function",
                    (CallNode::Leaf { kind, .. }, _) => kind.label(),
                };
                *census.entry((format!("{:?}", edge.kind), to)).or_default() += 1;
            })?;
            let warm = warm.elapsed();
            let total = size.edges.max(1);
            let share = |to: &str| {
                let count: usize = census.iter().filter(|((_, target), _)| *target == to).map(|(_, count)| count).sum();
                format!("{count} ({:.2}%)", count as f64 * 100.0 / total as f64)
            };
            writeln!(out, "records {}, functions {}, edges {}", size.records, size.functions, size.edges)?;
            writeln!(out, "external {}, unlinked {}, unresolved {}", share("external"), share("unlinked"), share("unresolved"))?;
            for ((kind, to), count) in &census {
                writeln!(out, "{kind:<12} {to:<28} {count:>9}")?;
            }
            writeln!(out, "cold build {cold:?}, warm listing {warm:?}, analyses {} bytes", engine.memory_use().analyses)?;
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
