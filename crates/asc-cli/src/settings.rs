//! `asc config`: every setting with its value, where the value came
//! from, and what an `auto` value comes to on this machine right now.

use asc_engine::asc_cache::{DiskCache, DiskCapacity, ProcessRegistry, ProcessUsage, disk_space};
use asc_engine::config::{Config, Count, Key, Source};
use asc_engine::{CacheConfig, Device, auto_threads};
use asc_frontend::decompile::Settings as Decompile;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Print the config file's path (whether or not it exists).
    Path,
}

/// What the machine offers, as the `auto` values see it.
struct Machine {
    device: Device,
    /// `(free, total)` of the cache directory's file system.
    disk: Option<(u64, u64)>,
    /// The user's other registered asc processes.
    others: Vec<ProcessUsage>,
}

impl Machine {
    fn probe(config: &Config) -> Machine {
        let disk = config.cache_dir().as_deref().and_then(disk_space);
        let others = ProcessRegistry::default_dir().map(|d| ProcessRegistry::others_in(&d)).unwrap_or_default();
        Machine { device: Device::probe(), disk, others }
    }
}

/// One row: the setting and, for an automatic value, what it is now.
struct Row {
    key: &'static Key,
    value: String,
    source: &'static str,
    now: Option<String>,
}

fn rows(config: &Config, machine: &Machine) -> Vec<Row> {
    config
        .entries()
        .into_iter()
        .map(|(key, value, source, auto)| Row {
            key,
            value,
            source: if source == Source::Default && auto { "auto" } else { source.name() },
            now: now(config, machine, key.name),
        })
        .collect()
}

fn gib(bytes: u64) -> String {
    format!("{:.1}G", bytes as f64 / f64::from(1u32 << 30))
}

/// One row per decompiler backend: name, command line, where it is
/// defined, and its part in the chains (`default`, `fallback N`, for
/// HarmonyOS programs `harmony default`, `harmony fallback N`, joined with
/// `, `; `disabled`, or `-`).
fn decompiler_rows(config: &Config) -> Vec<(String, String, &'static str, String)> {
    let decompile = Decompile::from_config(config);
    let role = |name: &str, default: &str, fallback: &[String], prefix: &str| {
        if name == default {
            Some(format!("{prefix}default"))
        } else {
            fallback.iter().position(|f| f == name).map(|i| format!("{prefix}fallback {}", i + 1))
        }
    };
    decompile
        .backends
        .iter()
        .map(|(name, entry)| {
            let roles: Vec<String> = [
                role(name, &decompile.default, &decompile.fallback, ""),
                role(name, &decompile.harmony_default, &decompile.harmony_fallback, "harmony "),
            ]
            .into_iter()
            .flatten()
            .collect();
            let role = match roles.is_empty() {
                _ if !entry.enabled => "disabled".to_string(),
                true => "-".to_string(),
                false => roles.join(", "),
            };
            (name.clone(), entry.command_line(), entry.origin.name(), role)
        })
        .collect()
}

/// What a setting comes to on this machine, where that is not its text.
fn now(config: &Config, m: &Machine, key: &str) -> Option<String> {
    let busy = m.others.iter().filter(|o| o.busy == Some(true)).count();
    match key {
        "threads" if config.threads.value == Count::Auto => {
            Some(format!("{} ({} CPUs, {busy} other busy processes)", auto_threads(), m.device.cpus))
        }
        "memory.max" => {
            let policy = config.memory_policy(&m.device)?;
            let share = policy.share(m.device.available_memory, 0, &m.others);
            let available = m.device.available_memory.map_or("unknown".into(), gib);
            let processes = if policy.split { m.others.len() + 1 } else { 1 };
            Some(format!("{} ({}% of {available} available, {processes} resident processes)", gib(share as u64), policy.percent))
        }
        "memory.ceiling" => config.memory_policy(&m.device).map(|p| gib(p.ceiling as u64)),
        "cache.dir" => Some(config.cache_dir().map_or("none (cache off)".into(), |d| d.display().to_string())),
        "cache.max" => {
            let DiskCapacity::Auto(auto) = config.disk_capacity() else { return None };
            let used = config.cache_dir().map_or(0, |d| DiskCache::open(d).stats().2);
            let free = m.disk.map_or("unknown".into(), |(free, total)| format!("{} free of {}", gib(free), gib(total)));
            Some(format!("{} ({}% of room, {} cached, {free})", gib(auto.bytes_for(m.disk, used)), auto.percent, gib(used)))
        }
        "cache.writers" if config.cache_writers.value == Count::Auto => Some(CacheConfig::auto_writers(m.device.cpus).to_string()),
        _ => None,
    }
}

pub(crate) fn print(config: &Config, action: Option<&ConfigAction>, json: bool) -> Result<u8, String> {
    let env = |name: &str| std::env::var(name).ok();
    if let Some(ConfigAction::Path) = action {
        let path = Config::file_path(env).ok_or("no config file: $ASC_CONFIG is empty and $HOME unset")?;
        println!("{}", path.display());
        return Ok(0);
    }
    let machine = Machine::probe(config);
    let rows = rows(config, &machine);
    let file = Config::file_path(env);
    let d = &machine.device;
    if json {
        let settings: Vec<_> = rows
            .iter()
            .map(|r| json!({ "key": r.key.name, "value": r.value, "source": r.source, "now": r.now, "env": r.key.env, "help": r.key.help }))
            .collect();
        let doc = json!({
            "file": file,
            "file_read": config.file.is_some(),
            "device": {
                "total_memory": d.total_memory,
                "available_memory": d.available_memory,
                "cpus": d.cpus,
                "disk_free": machine.disk.map(|s| s.0),
                "disk_total": machine.disk.map(|s| s.1),
                "other_processes": machine.others.len(),
            },
            "settings": settings,
            "decompilers": decompiler_rows(config)
                .into_iter()
                .map(|(name, command, source, role)| json!({"name": name, "command": command, "source": source, "role": role}))
                .collect::<Vec<_>>(),
        });
        println!("{doc}");
        return Ok(0);
    }
    let shown =
        file.as_ref().map_or("none".into(), |p| format!("{} ({})", p.display(), if config.file.is_some() { "read" } else { "not found" }));
    println!("# config file: {shown}");
    println!(
        "# machine: {} memory, {} available, {} CPUs, {} other asc processes",
        d.total_memory.map_or("unknown".into(), gib),
        d.available_memory.map_or("unknown".into(), gib),
        d.cpus,
        machine.others.len()
    );
    println!("# key | value | source | now");
    for r in &rows {
        println!("{} | {} | {} | {}", r.key.name, r.value, r.source, r.now.as_deref().unwrap_or("-"));
    }
    println!("# decompilers: name | command | source | role");
    for (name, command, source, role) in decompiler_rows(config) {
        println!("{name} | {command} | {source} | {role}");
    }
    println!(
        "# change: --set KEY=VALUE, the variable --json names (env), or the file ([memory] max = \"4G\"; [decompilers.NAME] command = ...)"
    );
    Ok(0)
}
