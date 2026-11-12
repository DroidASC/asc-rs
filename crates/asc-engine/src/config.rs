//! The user's configuration of threads, memory and the disk cache: one
//! table of settings ([`Config::KEYS`]), each taken from (first wins) a
//! command-line flag, its environment variable, the config file
//! ([`Config::file_path`]), or its default. `auto` defaults follow the
//! machine ([`Device`]) and the user's other busy processes.
//!
//! Values are text in every layer: sizes are bytes with an optional
//! `K`/`M`/`G`/`T` suffix (binary; a bare number is MiB), shares are
//! percentages (`25%`), switches are `on`/`off`, durations take
//! `ms`/`s`/`m`/`h` (a bare number is the key's unit).

use crate::{CacheConfig, Device, MemoryPolicy, Threads};
use asc_cache::{AutoDisk, DEFAULT_MIN_DEX_BYTES, DiskCache, DiskCapacity, Tier};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod decompilers;

pub use decompilers::{BUILT_IN_DECOMPILER, Decompiler};

/// Environment variable naming the config file; empty: none.
pub const CONFIG_ENV: &str = "ASC_CONFIG";

/// Where a setting's value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Source {
    /// The built-in default.
    Default,
    /// The config file.
    File,
    /// The setting's environment variable.
    Env,
    /// A command-line flag.
    Flag,
}

impl Source {
    /// `default`, `file`, `env` or `flag`, as shown to the user.
    pub fn name(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::File => "file",
            Source::Env => "env",
            Source::Flag => "flag",
        }
    }
}

/// A count of threads: `auto` or a positive number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Count {
    /// Computed from the machine and the user's busy processes.
    Auto,
    /// Exactly this many.
    Fixed(usize),
}

/// A budget: `auto`, a size, or a percentage of what the key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Amount {
    /// Computed from the machine (see the key's help).
    Auto,
    /// A fixed size in bytes.
    Bytes(u64),
    /// A percentage (0..=100) of what the key names.
    Percent(u8),
}

/// A size in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bytes(pub u64);

/// The disk cache directory: the platform default or a path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheDir {
    /// The platform default ([`DiskCache::default_dir`]).
    Default,
    /// This directory.
    Path(PathBuf),
}

/// The disk cache tiers in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tiers(pub [bool; 3]);

/// A duration whose bare numbers are seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seconds(pub Duration);

/// A duration whose bare numbers are milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Millis(pub Duration);

/// A name that is never empty (`decompile.default`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name(pub String);

/// Names, in order (`decompile.fallback`); `none` is the empty list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names(pub Vec<String>);

/// A file, or none (`decompile.mapping`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaybePath(pub Option<PathBuf>);

/// A setting's value type: parsed from and shown as the same text.
pub trait Value: Sized + fmt::Display {
    /// What the text may be, for error messages.
    const EXPECTED: &'static str;
    /// The value `text` spells, or `None` when it is not one.
    fn parse(text: &str) -> Option<Self>;
    /// Computed from the machine rather than given.
    fn is_auto(&self) -> bool {
        false
    }
}

const SIZE_UNITS: [(&str, u32); 5] = [("", 20), ("k", 10), ("m", 20), ("g", 30), ("t", 40)];

/// Bytes from `512`, `512M`, `4G`, `4GiB`, `1024k` (a bare number is MiB).
fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim().to_ascii_lowercase();
    let t = t.strip_suffix("ib").or_else(|| t.strip_suffix('b')).unwrap_or(&t);
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, unit) = t.split_at(split);
    let shift = SIZE_UNITS.iter().find(|(u, _)| *u == unit.trim())?.1;
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

fn show_size(bytes: u64) -> String {
    match SIZE_UNITS[1..].iter().rev().find(|(_, s)| bytes >= 1 << s && bytes.is_multiple_of(1 << s)) {
        Some((u, s)) => format!("{}{}", bytes >> s, u.to_ascii_uppercase()),
        None => format!("{bytes}B"),
    }
}

fn parse_duration(text: &str, bare: Duration) -> Option<Duration> {
    let t = text.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (n, unit) = t.split_at(split);
    let n: u32 = n.parse().ok()?;
    let unit = match unit.trim() {
        "" => bare,
        "ms" => Duration::from_millis(1),
        "s" => Duration::from_secs(1),
        "m" | "min" => Duration::from_secs(60),
        "h" => Duration::from_secs(3600),
        _ => return None,
    };
    unit.checked_mul(n)
}

fn show_duration(d: Duration) -> String {
    let ms = d.as_millis();
    match () {
        _ if ms > 0 && ms.is_multiple_of(3_600_000) => format!("{}h", ms / 3_600_000),
        _ if ms > 0 && ms.is_multiple_of(60_000) => format!("{}m", ms / 60_000),
        _ if ms.is_multiple_of(1000) => format!("{}s", ms / 1000),
        _ => format!("{ms}ms"),
    }
}

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Count::Auto => f.write_str("auto"),
            Count::Fixed(n) => write!(f, "{n}"),
        }
    }
}

impl Value for Count {
    const EXPECTED: &'static str = "auto or a number (0 counts as 1)";
    fn parse(text: &str) -> Option<Count> {
        match text.trim() {
            "auto" => Some(Count::Auto),
            n => n.parse().ok().map(Count::Fixed),
        }
    }
    fn is_auto(&self) -> bool {
        *self == Count::Auto
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Amount::Auto => f.write_str("auto"),
            Amount::Bytes(b) => f.write_str(&show_size(*b)),
            Amount::Percent(p) => write!(f, "{p}%"),
        }
    }
}

impl Value for Amount {
    const EXPECTED: &'static str = "auto, a size (512M, 4G; a bare number is MiB) or a percentage (25%)";
    fn parse(text: &str) -> Option<Amount> {
        let t = text.trim();
        if t == "auto" {
            return Some(Amount::Auto);
        }
        match t.strip_suffix('%') {
            Some(p) => p.trim().parse().ok().filter(|p| (1..=100).contains(p)).map(Amount::Percent),
            None => parse_size(t).map(Amount::Bytes),
        }
    }
    fn is_auto(&self) -> bool {
        *self == Amount::Auto
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&show_size(self.0))
    }
}

impl Value for Bytes {
    const EXPECTED: &'static str = "a size (512M, 4G; a bare number is MiB)";
    fn parse(text: &str) -> Option<Bytes> {
        parse_size(text).map(Bytes)
    }
}

impl Value for bool {
    const EXPECTED: &'static str = "on or off";
    fn parse(text: &str) -> Option<bool> {
        match text.trim().to_ascii_lowercase().as_str() {
            "on" | "true" | "yes" | "1" => Some(true),
            "off" | "false" | "no" | "0" => Some(false),
            _ => None,
        }
    }
}

impl fmt::Display for CacheDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheDir::Default => f.write_str("default"),
            CacheDir::Path(p) => write!(f, "{}", p.display()),
        }
    }
}

impl Value for CacheDir {
    const EXPECTED: &'static str = "a directory, or default";
    fn parse(text: &str) -> Option<CacheDir> {
        match text.trim() {
            "" => None,
            "default" => Some(CacheDir::Default),
            p => Some(CacheDir::Path(expand_home(p))),
        }
    }
}

/// `~/x` under `$HOME`.
fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

impl fmt::Display for Tiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = Tier::ALL.into_iter().filter(|t| self.0[*t as usize]).map(Tier::name).collect();
        f.write_str(if names.is_empty() { "none".into() } else { names.join(",") }.as_str())
    }
}

impl Value for Tiers {
    const EXPECTED: &'static str = "a list of dex, derived, rendered (or all, none)";
    fn parse(text: &str) -> Option<Tiers> {
        match text.trim() {
            "all" => return Some(Tiers([true; 3])),
            "none" => return Some(Tiers([false; 3])),
            _ => {}
        }
        let mut on = [false; 3];
        for name in text.split(',').map(str::trim) {
            on[*Tier::ALL.iter().find(|t| t.name() == name)? as usize] = true;
        }
        Some(Tiers(on))
    }
}

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&show_duration(self.0))
    }
}

impl Value for Seconds {
    const EXPECTED: &'static str = "a duration (900, 15m; a bare number is seconds)";
    fn parse(text: &str) -> Option<Seconds> {
        parse_duration(text, Duration::from_secs(1)).map(Seconds)
    }
}

impl fmt::Display for Millis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&show_duration(self.0))
    }
}

impl Value for Millis {
    const EXPECTED: &'static str = "a duration (300, 2s; a bare number is milliseconds)";
    fn parse(text: &str) -> Option<Millis> {
        parse_duration(text, Duration::from_millis(1)).map(Millis)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Value for Name {
    const EXPECTED: &'static str = "a name";
    fn parse(text: &str) -> Option<Name> {
        Some(text.trim()).filter(|t| !t.is_empty() && !t.contains(',')).map(|t| Name(t.to_string()))
    }
}

impl fmt::Display for Names {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_empty() { "none".into() } else { self.0.join(",") }.as_str())
    }
}

impl Value for Names {
    const EXPECTED: &'static str = "names separated by `,` (or none)";
    fn parse(text: &str) -> Option<Names> {
        if matches!(text.trim(), "" | "none") {
            return Some(Names::default());
        }
        text.split(',').map(|name| Name::parse(name).map(|n| n.0)).collect::<Option<_>>().map(Names)
    }
}

impl fmt::Display for MaybePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(path) => write!(f, "{}", path.display()),
            None => f.write_str("none"),
        }
    }
}

impl Value for MaybePath {
    const EXPECTED: &'static str = "a file, or none";
    fn parse(text: &str) -> Option<MaybePath> {
        match text.trim() {
            "" | "none" => Some(MaybePath(None)),
            p => Some(MaybePath(Some(expand_home(p)))),
        }
    }
}

/// A value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Setting<T> {
    /// The resolved value.
    pub value: T,
    /// The layer it came from.
    pub source: Source,
}

/// One row of [`Config::KEYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Key {
    /// Name in the config file (`section.name`) and in `--set`.
    pub name: &'static str,
    /// Environment variable that sets it (`ASC_...`).
    pub env: &'static str,
    /// An older variable read when `env` is unset.
    pub legacy_env: Option<&'static str>,
    /// One-line description, with what `auto` means where it applies.
    pub help: &'static str,
}

/// Why a configuration could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A value that does not parse as its key's type.
    #[error("{origin}: {key} = {text:?}: expected {expected}")]
    Invalid {
        /// The layer that gave it: `command line`, `$VAR`, or the file path.
        origin: String,
        /// The setting's name.
        key: String,
        /// The text given.
        text: String,
        /// What the text may be ([`Value::EXPECTED`]).
        expected: &'static str,
    },
    /// A setting name not in [`Config::KEYS`].
    #[error("{origin}: unknown setting {key:?}; known: {known}")]
    UnknownKey {
        /// The layer that gave it.
        origin: String,
        /// The unknown name.
        key: String,
        /// Every known name, comma-separated.
        known: String,
    },
    /// The config file could not be read or is not valid TOML.
    #[error("{path}: {message}")]
    File {
        /// The config file.
        path: String,
        /// What went wrong.
        message: String,
    },
}

/// Declares the settings once: the struct, its key table, defaults and
/// text access all come from this list.
macro_rules! settings {
    ($($field:ident: $ty:ty = $default:expr, $name:literal, $env:literal, $legacy:expr, $help:literal;)*) => {
        /// The resolved settings ([`Config::resolve`]).
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub struct Config {
            $(#[doc = concat!("`", $name, "`: ", $help, ".")]
            pub $field: Setting<$ty>,)*
            /// The config file read, if any.
            pub file: Option<PathBuf>,
            /// `[decompilers.<name>]` tables of the config file, by name.
            pub decompilers: BTreeMap<String, Decompiler>,
        }

        impl Config {
            /// Every setting, in declaration order.
            pub const KEYS: &'static [Key] = &[$(Key { name: $name, env: $env, legacy_env: $legacy, help: $help },)*];

            fn defaults() -> Config {
                Config { $($field: Setting { value: $default, source: Source::Default },)* file: None, decompilers: BTreeMap::new() }
            }

            /// Set `name` from `text`; `origin` names the layer in errors.
            fn set(&mut self, name: &str, text: &str, source: Source, origin: &str) -> Result<(), ConfigError> {
                match name {
                    $($name => self.$field = Setting { value: parse_value(name, text, origin)?, source },)*
                    _ => return Err(ConfigError::UnknownKey { origin: origin.into(), key: name.into(), known: Config::known_keys() }),
                }
                Ok(())
            }

            /// `(key, value text, source, computed from the machine)` of every setting, in [`Config::KEYS`] order.
            pub fn entries(&self) -> Vec<(&'static Key, String, Source, bool)> {
                let mut keys = Config::KEYS.iter();
                vec![$({
                    let key = keys.next().expect("one key per setting");
                    (key, self.$field.value.to_string(), self.$field.source, self.$field.value.is_auto())
                },)*]
            }
        }
    };
}

settings! {
    threads: Count = Count::Auto, "threads", "ASC_THREADS", None,
        "worker threads per process; auto: the CPUs, 4 per CPU split between busy asc processes";
    memory_max: Amount = Amount::Auto, "memory.max", "ASC_MEMORY", None,
        "memory cache of mcp and the daemon; auto = 25%: of available memory, split between resident processes";
    memory_ceiling: Amount = Amount::Auto, "memory.ceiling", "ASC_MEMORY_CEILING", None,
        "most one process's automatic memory cache takes (a % is of physical memory); auto: 1/16 of it, 2G..8G";
    memory_split: bool = true, "memory.split", "ASC_MEMORY_SPLIT", None,
        "split the automatic memory budget between the user's resident processes";
    cache_enabled: bool = true, "cache.enabled", "ASC_CACHE", None,
        "read and write the disk cache";
    cache_dir: CacheDir = CacheDir::Default, "cache.dir", "ASC_CACHE_DIR", None,
        "disk cache directory; default: $XDG_CACHE_HOME/asc or ~/.cache/asc";
    cache_max: Amount = Amount::Auto, "cache.max", "ASC_CACHE_MAX", Some("ASC_CACHE_MAX_MB"),
        "disk cache budget; auto = 20%: of free space plus the cache, at most cache.ceiling, never into a 1 GiB / 5% reserve";
    cache_ceiling: Bytes = Bytes(AutoDisk::CEILING), "cache.ceiling", "ASC_CACHE_CEILING", None,
        "most the automatic disk budget takes";
    cache_tiers: Tiers = Tiers([true; 3]), "cache.tiers", "ASC_CACHE_TIERS", None,
        "disk cache tiers in use: dex (L1), derived (L2), rendered (L3)";
    cache_min_dex: Bytes = Bytes(DEFAULT_MIN_DEX_BYTES), "cache.min_dex", "ASC_CACHE_MIN_DEX", Some("ASC_CACHE_MIN_DEX_MB"),
        "smallest inflated DEX written to L1 (smaller ones are cheaper to inflate again)";
    cache_write_queue: Bytes = Bytes(CacheConfig::WRITE_QUEUE as u64), "cache.write_queue", "ASC_CACHE_WRITE_QUEUE", None,
        "heap queued disk writes may hold (at most the memory cache's budget); later ones inflate again when written";
    cache_writers: Count = Count::Auto, "cache.writers", "ASC_CACHE_WRITERS", None,
        "disk writer threads per process; auto: 1 per 8 CPUs, 1..4";
    cache_spill: Bytes = Bytes(64 << 20), "cache.spill", "ASC_CACHE_SPILL", None,
        "budget of out/ in the cache directory, where cut outputs go; 0 writes none";
    daemon_idle: Seconds = Seconds(Duration::from_secs(15 * 60)), "daemon.idle", "ASC_DAEMON_IDLE", None,
        "the daemon exits after this long without a request";
    daemon_wait: Millis = Millis(Duration::from_millis(300)), "daemon.wait", "ASC_DAEMON_WAIT", Some("ASC_DAEMON_WAIT_MS"),
        "how long the first command waits for the daemon it starts, then runs itself";
    decompile_default: Name = Name(String::from("dexdec")), "decompile.default", "ASC_DECOMPILER", None,
        "backend of asc decompile unless --decompiler names one (a [decompilers.NAME] table, or the built-in dexdec)";
    decompile_fallback: Names = Names::default(), "decompile.fallback", "ASC_DECOMPILE_FALLBACK", None,
        "backends tried in order when the default one fails on a whole class; none: smali right away";
    decompile_mapping: MaybePath = MaybePath::default(), "decompile.mapping", "ASC_MAPPING", None,
        "R8 / ProGuard mapping.txt whose names decompiled source shows (--mapping); none: the DEX's own names";
    decompile_auto_install: bool = true, "decompile.auto_install", "ASC_AUTO_INSTALL", None,
        "download asc-dexdec-worker speaking this asc's protocol version from decompile.release_url when no worker is found";
    decompile_release_url: Name = Name(String::from(DEFAULT_RELEASE_URL)), "decompile.release_url", "ASC_RELEASE_URL", None,
        "where asc install and the auto-install fetch the worker: URL/asc-dexdec-worker-pPROTOCOL-TARGET.tar.gz";
}

/// The downloads of the latest asc-dexdec-worker release, the default
/// `decompile.release_url`.
pub const DEFAULT_RELEASE_URL: &str = "https://github.com/DroidASC/asc-dexdec/releases/latest/download";

/// Settings whose file value may be an array of strings, read as the names
/// joined with `,`.
const LIST_KEYS: &[&str] = &["decompile.fallback"];

/// `[section] key = v` as `("section.key", v)`.
fn flatten<'t>(prefix: &str, table: &'t toml::Table, out: &mut Vec<(String, &'t toml::Value)>) {
    for (k, v) in table {
        let name = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match v {
            toml::Value::Table(t) => flatten(&name, t, out),
            v => out.push((name, v)),
        }
    }
}

fn parse_value<T: Value>(key: &str, text: &str, origin: &str) -> Result<T, ConfigError> {
    T::parse(text).ok_or_else(|| ConfigError::Invalid { origin: origin.into(), key: key.into(), text: text.into(), expected: T::EXPECTED })
}

impl Config {
    fn known_keys() -> String {
        Config::KEYS.iter().map(|k| k.name).collect::<Vec<_>>().join(", ")
    }

    /// The config file: `$ASC_CONFIG` (empty: none), else
    /// `$XDG_CONFIG_HOME/asc/config.toml`, else
    /// `~/.config/asc/config.toml`.
    pub fn file_path(env: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
        if let Some(p) = env(CONFIG_ENV) {
            return (!p.is_empty()).then(|| expand_home(&p));
        }
        let base = env("XDG_CONFIG_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| env("HOME").map(|h| Path::new(&h).join(".config")))?;
        Some(base.join("asc").join("config.toml"))
    }

    /// Read the process's environment and config file, then apply `flags`
    /// (`(key, value)` pairs from the command line).
    ///
    /// # Errors
    ///
    /// [`ConfigError::File`] when the config file exists but cannot be read,
    /// and the errors of [`Config::resolve`].
    pub fn load(flags: &[(String, String)]) -> Result<Config, ConfigError> {
        let env = |name: &str| std::env::var(name).ok();
        let file = match Config::file_path(env) {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(text) => Some((path, text)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(ConfigError::File { path: path.display().to_string(), message: e.to_string() }),
            },
            None => None,
        };
        Config::resolve(file.as_ref().map(|(p, t)| (p.as_path(), t.as_str())), env, flags)
    }

    /// Defaults, then the file `(path, text)`, then `env`, then `flags`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::File`] when the file is not valid TOML,
    /// [`ConfigError::UnknownKey`] for a name not in [`Config::KEYS`], and
    /// [`ConfigError::Invalid`] for a value that does not parse.
    pub fn resolve(
        file: Option<(&Path, &str)>,
        env: impl Fn(&str) -> Option<String>,
        flags: &[(String, String)],
    ) -> Result<Config, ConfigError> {
        let mut config = Config::defaults();
        if let Some((path, text)) = file {
            config.apply_file(path, text)?;
            config.file = Some(path.to_path_buf());
        }
        for key in Config::KEYS {
            let found =
                [Some(key.env), key.legacy_env].into_iter().flatten().find_map(|var| Some((var, env(var).filter(|v| !v.is_empty())?)));
            if let Some((var, text)) = found {
                config.set(key.name, &text, Source::Env, &format!("${var}"))?;
            }
        }
        for (name, text) in flags {
            config.set(name, text, Source::Flag, "command line")?;
        }
        Ok(config)
    }

    fn apply_file(&mut self, path: &Path, text: &str) -> Result<(), ConfigError> {
        let origin = path.display().to_string();
        let mut table: toml::Table =
            text.parse().map_err(|e: toml::de::Error| ConfigError::File { path: origin.clone(), message: e.message().to_string() })?;
        // Tables of their own, not settings: taken out before the rest is flattened.
        if let Some(decompilers) = table.remove("decompilers") {
            self.decompilers = Decompiler::parse_all(&decompilers, &origin)?;
        }
        let mut pairs = Vec::new();
        flatten("", &table, &mut pairs);
        for (name, value) in pairs {
            let text = match value {
                toml::Value::String(s) => s.clone(),
                toml::Value::Integer(i) => i.to_string(),
                toml::Value::Boolean(b) => b.to_string(),
                toml::Value::Array(items) if LIST_KEYS.contains(&name.as_str()) => {
                    let names: Option<Vec<&str>> = items.iter().map(toml::Value::as_str).collect();
                    match names {
                        Some(names) if names.is_empty() => "none".to_string(),
                        Some(names) => names.join(","),
                        None => {
                            return Err(ConfigError::Invalid {
                                origin,
                                key: name,
                                text: "<array>".into(),
                                expected: "an array of strings",
                            });
                        }
                    }
                }
                other => {
                    return Err(ConfigError::Invalid {
                        origin,
                        key: name,
                        text: format!("<{}>", other.type_str()),
                        expected: "a string, number or boolean",
                    });
                }
            };
            self.set(&name, &text, Source::File, &origin)?;
        }
        Ok(())
    }

    /// The `(key, value)` pairs of the settings given on the command line,
    /// to hand on to a process started for this one (a daemon).
    pub fn flag_pairs(&self) -> Vec<(String, String)> {
        self.entries()
            .into_iter()
            .filter(|(_, _, source, _)| *source == Source::Flag)
            .map(|(key, text, _, _)| (key.name.to_string(), text))
            .collect()
    }

    /// The `threads` setting as the engine takes it.
    pub fn threads(&self) -> Threads {
        match self.threads.value {
            Count::Auto => Threads::Auto,
            Count::Fixed(n) => Threads::Fixed(n),
        }
    }

    /// [`Config::threads`] as an explicit count, `None` for auto.
    pub fn fixed_threads(&self) -> Option<usize> {
        match self.threads.value {
            Count::Auto => None,
            Count::Fixed(n) => Some(n),
        }
    }

    /// How an automatic memory cache follows `device`; `None` for a fixed size.
    pub fn memory_policy(&self, device: &Device) -> Option<MemoryPolicy> {
        let percent = match self.memory_max.value {
            Amount::Bytes(_) => return None,
            Amount::Auto => MemoryPolicy::PERCENT,
            Amount::Percent(p) => p,
        };
        Some(MemoryPolicy { percent, ceiling: self.memory_ceiling(device), split: self.memory_split.value })
    }

    fn memory_ceiling(&self, device: &Device) -> usize {
        match self.memory_ceiling.value {
            Amount::Auto => MemoryPolicy::auto_ceiling(device.total_memory),
            Amount::Bytes(b) => usize::try_from(b).unwrap_or(usize::MAX),
            Amount::Percent(p) => device
                .total_memory
                .map_or(MemoryPolicy::CEILING_MIN, |t| usize::try_from(u128::from(t) * u128::from(p) / 100).unwrap_or(usize::MAX)),
        }
    }

    /// The memory cache's starting size on `device`.
    pub fn memory_bytes(&self, device: &Device) -> usize {
        match self.memory_policy(device) {
            Some(policy) => policy.alone(device.available_memory),
            None => match self.memory_max.value {
                Amount::Bytes(b) => usize::try_from(b).unwrap_or(usize::MAX),
                Amount::Auto | Amount::Percent(_) => MemoryPolicy::CEILING_MIN,
            },
        }
    }

    /// The cache directory in use (`None`: the cache is off, or no default
    /// directory could be determined).
    pub fn cache_dir(&self) -> Option<PathBuf> {
        if !self.cache_enabled.value {
            return None;
        }
        match &self.cache_dir.value {
            CacheDir::Default => DiskCache::default_dir(),
            CacheDir::Path(p) => Some(p.clone()),
        }
    }

    /// The disk cache budget from `cache.max` and `cache.ceiling`.
    pub fn disk_capacity(&self) -> DiskCapacity {
        let ceiling = self.cache_ceiling.value.0;
        match self.cache_max.value {
            Amount::Auto => DiskCapacity::Auto(AutoDisk::new(AutoDisk::PERCENT, ceiling)),
            Amount::Percent(percent) => DiskCapacity::Auto(AutoDisk::new(percent, ceiling)),
            Amount::Bytes(b) => DiskCapacity::Fixed(b),
        }
    }

    /// The disk cache, unless it is off.
    pub fn disk_cache(&self) -> Option<DiskCache> {
        let tiers: Vec<Tier> = Tier::ALL.into_iter().filter(|t| self.cache_tiers.value.0[*t as usize]).collect();
        Some(
            DiskCache::open(self.cache_dir()?)
                .with_capacity_mode(self.disk_capacity())
                .with_tiers(&tiers)
                .with_min_dex_bytes(self.cache_min_dex.value.0),
        )
    }

    fn writers(&self) -> Option<usize> {
        match self.cache_writers.value {
            Count::Auto => None,
            Count::Fixed(n) => Some(n),
        }
    }

    /// The cache of a one-shot command: the disk cache only.
    pub fn one_shot_cache(&self) -> CacheConfig {
        CacheConfig {
            disk: self.disk_cache(),
            writers: self.writers(),
            write_queue_bytes: self.write_queue_bytes(),
            ..CacheConfig::default()
        }
    }

    /// The cache of a resident host (`mcp`, the daemon) on `device`.
    pub fn resident_cache(&self, device: &Device) -> CacheConfig {
        CacheConfig {
            memory_bytes: self.memory_bytes(device),
            disk: self.disk_cache(),
            memory_auto: self.memory_policy(device),
            write_queue_bytes: self.write_queue_bytes(),
            writers: self.writers(),
        }
    }

    fn write_queue_bytes(&self) -> usize {
        usize::try_from(self.cache_write_queue.value.0).unwrap_or(usize::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const GIB: u64 = 1 << 30;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let vars: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| vars.get(k).cloned()
    }

    fn flags(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn values_parse_and_show_the_same_text() {
        assert_eq!(Amount::parse("512"), Some(Amount::Bytes(512 << 20)));
        assert_eq!(Amount::parse(" 4G "), Some(Amount::Bytes(4 * GIB)));
        assert_eq!(Amount::parse("4GiB"), Some(Amount::Bytes(4 * GIB)));
        assert_eq!(Amount::parse("1024k"), Some(Amount::Bytes(1 << 20)));
        assert_eq!(Amount::parse("25%"), Some(Amount::Percent(25)));
        assert_eq!(Amount::parse("0%"), None);
        assert_eq!(Amount::parse("lots"), None);
        assert_eq!(Amount::Bytes(6 * GIB).to_string(), "6G");
        assert_eq!(Amount::Bytes(1536 << 20).to_string(), "1536M");
        assert_eq!(Bytes(0).to_string(), "0B");
        assert_eq!(Count::parse("-1"), None);
        assert_eq!(Count::parse("8"), Some(Count::Fixed(8)));
        assert_eq!(Tiers::parse("dex, rendered"), Some(Tiers([true, false, true])));
        assert_eq!(Tiers::parse("l1"), None);
        assert_eq!(Tiers([false; 3]).to_string(), "none");
        assert_eq!(Seconds::parse("15m").map(|s| s.0), Some(Duration::from_secs(900)));
        assert_eq!(Seconds::parse("2").map(|s| s.to_string()).as_deref(), Some("2s"));
        assert_eq!(Millis::parse("300").map(|s| s.to_string()).as_deref(), Some("300ms"));
        assert_eq!(bool::parse("OFF"), Some(false));
        for (key, text, _, _) in Config::defaults().entries() {
            assert!(Config::defaults().set(key.name, &text, Source::Flag, "test").is_ok(), "{} = {text} does not read back", key.name);
        }
    }

    #[test]
    fn flags_beat_env_beat_file_beat_defaults() {
        let file = "threads = 3\n[memory]\nmax = \"30%\"\nsplit = false\n[cache]\nmax = \"8G\"\ntiers = \"dex\"\n";
        let path = Path::new("/etc/asc.toml");
        let c =
            Config::resolve(Some((path, file)), env(&[("ASC_THREADS", "6"), ("ASC_CACHE_MAX_MB", "1024")]), &flags(&[("threads", "9")]))
                .unwrap();
        assert_eq!(c.threads, Setting { value: Count::Fixed(9), source: Source::Flag });
        assert_eq!(c.cache_max, Setting { value: Amount::Bytes(GIB), source: Source::Env });
        assert_eq!(c.memory_max, Setting { value: Amount::Percent(30), source: Source::File });
        assert!(!c.memory_split.value);
        assert_eq!(c.cache_tiers.value, Tiers([true, false, false]));
        assert_eq!(c.cache_dir.source, Source::Default);
        assert_eq!(c.file.as_deref(), Some(path));
        assert_eq!(c.flag_pairs(), flags(&[("threads", "9")]));
        // The current name wins over the legacy one; empty variables are unset.
        let c = Config::resolve(None, env(&[("ASC_CACHE_MAX", "20%"), ("ASC_CACHE_MAX_MB", "1"), ("ASC_THREADS", "")]), &[]).unwrap();
        assert_eq!(c.cache_max.value, Amount::Percent(20));
        assert_eq!(c.threads.source, Source::Default);
    }

    #[test]
    fn errors_say_where_and_what_is_expected() {
        let e = Config::resolve(None, env(&[("ASC_MEMORY", "lots")]), &[]).unwrap_err().to_string();
        assert!(e.contains("$ASC_MEMORY: memory.max = \"lots\": expected auto, a size"), "{e}");
        let e = Config::resolve(Some((Path::new("c.toml"), "[memory]\nmaxx = 1\n")), env(&[]), &[]).unwrap_err().to_string();
        assert!(e.starts_with("c.toml: unknown setting \"memory.maxx\"; known: threads, memory.max"), "{e}");
        let e = Config::resolve(Some((Path::new("c.toml"), "threads = [1]\n")), env(&[]), &[]).unwrap_err().to_string();
        assert!(e.contains("expected a string, number or boolean"), "{e}");
        let e = Config::resolve(Some((Path::new("c.toml"), "threads = \n")), env(&[]), &[]).unwrap_err().to_string();
        assert!(e.starts_with("c.toml: "), "{e}");
        let e = Config::resolve(None, env(&[]), &flags(&[("cache.tiers", "l1")])).unwrap_err().to_string();
        assert!(e.contains("command line: cache.tiers = \"l1\": expected a list of dex, derived, rendered"), "{e}");
    }

    #[test]
    fn the_file_is_found_like_other_xdg_configs() {
        assert_eq!(Config::file_path(env(&[("HOME", "/h")])), Some(PathBuf::from("/h/.config/asc/config.toml")));
        assert_eq!(Config::file_path(env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x")])), Some(PathBuf::from("/x/asc/config.toml")));
        assert_eq!(Config::file_path(env(&[("HOME", "/h"), (CONFIG_ENV, "/c.toml")])), Some(PathBuf::from("/c.toml")));
        assert_eq!(Config::file_path(env(&[("HOME", "/h"), (CONFIG_ENV, "")])), None);
    }

    #[test]
    fn auto_values_follow_the_device() {
        let laptop = Device { total_memory: Some(12 * GIB), available_memory: Some(6 * GIB), cpus: 16 };
        let big = Device { total_memory: Some(96 * GIB), available_memory: Some(60 * GIB), cpus: 32 };
        let c = Config::defaults();
        assert_eq!(c.memory_bytes(&laptop), (6 * GIB / 4) as usize);
        assert_eq!(c.memory_bytes(&big), 6 << 30);
        assert_eq!(c.memory_policy(&big), Some(MemoryPolicy { percent: 25, ceiling: 6 << 30, split: true }));
        let c = Config::resolve(None, env(&[]), &flags(&[("memory.max", "10%"), ("memory.ceiling", "50%")])).unwrap();
        assert_eq!(c.memory_bytes(&big), (60 * GIB / 10) as usize);
        assert_eq!(c.memory_policy(&big).unwrap().ceiling, (48 * GIB) as usize);
        let c = Config::resolve(None, env(&[]), &flags(&[("memory.max", "1G")])).unwrap();
        assert_eq!((c.memory_bytes(&big), c.memory_policy(&big)), (GIB as usize, None));
        let c = Config::resolve(None, env(&[]), &flags(&[("cache.max", "10%"), ("cache.ceiling", "5G")])).unwrap();
        assert_eq!(c.disk_capacity(), DiskCapacity::Auto(AutoDisk::new(10, 5 * GIB)));
        let off = Config::resolve(None, env(&[("ASC_CACHE", "off")]), &[]).unwrap();
        assert!(off.disk_cache().is_none() && off.cache_dir().is_none());
        let fixed = Config::resolve(None, env(&[]), &flags(&[("threads", "4"), ("cache.writers", "2"), ("cache.dir", "/tmp/c")])).unwrap();
        assert_eq!((fixed.threads(), fixed.fixed_threads()), (Threads::Fixed(4), Some(4)));
        let cache = fixed.resident_cache(&laptop);
        assert_eq!((cache.writers, cache.write_queue_bytes), (Some(2), CacheConfig::WRITE_QUEUE));
        assert_eq!(cache.disk.unwrap().dir(), Path::new("/tmp/c"));
    }
}
