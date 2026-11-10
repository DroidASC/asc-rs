//! Measurement, not a feature: the callee of every call site by where it
//! comes from, before and after captured variables are resolved, and why
//! the unresolved ones are (`docs/ark-abc-design.md` §7).
//!
//! ```text
//! lexstats [--records SUBSTRING] [--threads N] [--samples] <path>
//! ```
//!
//! `--samples` prints one tab-separated line per call site whose callee
//! starts at a resolved captured variable instead of the tables:
//! `record, function, call pc, ldlexvar pc, level, slot, callee, writer
//! function, stlexvar pc, file offset of the function's code, file offset
//! of the writer's code`.

use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use asc_ark_engine::{CalleeRoot, Engine, ResolutionOptions, Unresolved};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut value = |flag: &str| {
        let at = args.iter().position(|arg| arg == flag)?;
        args.remove(at);
        (at < args.len()).then(|| args.remove(at))
    };
    let records = value("--records");
    let threads = value("--threads").map(|n| n.parse::<usize>()).transpose()?;
    let samples = args.iter().any(|arg| arg == "--samples");
    args.retain(|arg| arg != "--samples");
    let [path] = &args[..] else { return Err("usage: lexstats [--records SUBSTRING] [--threads N] [--samples] <path>".into()) };
    let mut engine = Engine::open(path)?;
    if let Some(threads) = threads {
        engine = engine.with_threads(threads);
    }
    let started = Instant::now();
    let stats = engine.call_resolution(&ResolutionOptions { records: records.as_deref(), samples }, &AtomicBool::new(false))?;
    let elapsed = started.elapsed();
    if samples {
        for s in &stats.samples {
            println!(
                "{}\t{}\t{:#x}\t{:#x}\t{}\t{}\t{}\t{}\t{:#x}\t{:#x}\t{:#x}",
                s.record,
                s.function,
                s.call_pc,
                s.load_pc,
                s.level,
                s.slot,
                s.callee,
                s.writer,
                s.writer_pc,
                s.function_code,
                s.writer_code
            );
        }
        return Ok(());
    }
    let total = stats.call_sites.max(1) as f64;
    println!("{} records ({} with scopes), {} call sites, {elapsed:?}", stats.records, stats.scoped_records, stats.call_sites);
    println!("{:<18} {:>9} {:>6}   {:>9} {:>6}", "root", "before", "%", "after", "%");
    for root in CalleeRoot::ALL {
        let (before, after) = (stats.before.get(&root).copied().unwrap_or(0), stats.after.get(&root).copied().unwrap_or(0));
        let percent = |count: usize| 100.0 * count as f64 / total;
        println!("{:<18} {before:>9} {:>5.1}%   {after:>9} {:>5.1}%", format!("{root:?}"), percent(before), percent(after));
    }
    let captured = stats.captured.max(1) as f64;
    println!(
        "captured callees: {} resolved {} ({:.1}%)",
        stats.captured,
        stats.captured_resolved,
        100.0 * stats.captured_resolved as f64 / captured
    );
    for why in Unresolved::ALL {
        let count = stats.captured_unresolved.get(&why).copied().unwrap_or(0);
        println!("  {:<34} {count:>8} {:>5.1}%", why.label(), 100.0 * count as f64 / captured);
    }
    println!("{:#?}", stats.scopes);
    Ok(())
}
