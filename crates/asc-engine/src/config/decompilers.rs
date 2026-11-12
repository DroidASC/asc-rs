//! `[decompilers.<name>]`: how to run each decompiler backend
//! (docs/decompile-backends.md §4). Unlike the settings, these are whole
//! tables (an argument list, an environment, options passed through), so
//! they are read before the rest of the file is flattened into keys.

use super::{ConfigError, expand_home, parse_duration};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// One `[decompilers.<name>]` table. Defaults follow §4.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decompiler {
    /// `command`: the executable; looked up on `PATH` when it has no `/`.
    /// Only the built-in backend ([`BUILT_IN_DECOMPILER`]) may leave it out,
    /// to change its other keys and keep the `asc-dexdec-worker` asc finds.
    pub command: Option<PathBuf>,
    /// `args`.
    pub args: Vec<String>,
    /// `env`: added to the inherited environment.
    pub env: BTreeMap<String, String>,
    /// `cwd`; `None`: `decompilers/<name>/` in the cache directory.
    pub cwd: Option<PathBuf>,
    /// `instances`: processes in the pool, at least 1.
    pub instances: usize,
    /// `max_concurrency`: caps the requests one process takes at once
    /// (the backend declares its own limit); `None`: as declared.
    pub max_concurrency: Option<u32>,
    /// `idle`: a process idle this long exits.
    pub idle: Duration,
    /// `timeout`: deadline of one request.
    pub timeout: Duration,
    /// `startup_timeout`: deadline of the `initialize` handshake.
    pub startup_timeout: Duration,
    /// `inputs`: the input kinds asc may hand the backend (`archive`,
    /// `slice`); empty: whatever it declares.
    pub inputs: Vec<String>,
    /// `options`: passed through to `initialize` uninterpreted.
    pub options: serde_json::Map<String, serde_json::Value>,
    /// `enabled`: `false` keeps the table but never starts the backend.
    pub enabled: bool,
}

/// Keys of a table, for the error naming an unknown one.
const KEYS: &[&str] = &[
    "command",
    "args",
    "env",
    "cwd",
    "instances",
    "max_concurrency",
    "idle",
    "timeout",
    "startup_timeout",
    "inputs",
    "options",
    "enabled",
];

/// The name of asc's own backend, `asc-dexdec-worker`.
pub const BUILT_IN_DECOMPILER: &str = "dexdec";

/// What `inputs` may list.
const INPUT_KINDS: &[&str] = &["archive", "slice"];

impl Decompiler {
    /// A backend run as `command` with every other key at its default.
    pub fn new(command: impl Into<PathBuf>) -> Decompiler {
        Decompiler {
            command: Some(command.into()),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            instances: 1,
            max_concurrency: None,
            idle: Duration::from_secs(10 * 60),
            timeout: Duration::from_secs(60),
            startup_timeout: Duration::from_secs(30),
            inputs: Vec::new(),
            options: serde_json::Map::new(),
            enabled: true,
        }
    }

    /// Every table under `[decompilers]` of the file `origin`.
    pub(super) fn parse_all(value: &toml::Value, origin: &str) -> Result<BTreeMap<String, Decompiler>, ConfigError> {
        let invalid =
            |key: String, text: String, expected: &'static str| ConfigError::Invalid { origin: origin.into(), key, text, expected };
        let toml::Value::Table(tables) = value else {
            return Err(invalid("decompilers".into(), format!("<{}>", value.type_str()), "a table of [decompilers.NAME] tables"));
        };
        tables
            .iter()
            .map(|(name, table)| {
                let toml::Value::Table(table) = table else {
                    return Err(invalid(format!("decompilers.{name}"), format!("<{}>", table.type_str()), "a table"));
                };
                Ok((name.clone(), Decompiler::parse(name, table, origin)?))
            })
            .collect()
    }

    fn parse(name: &str, table: &toml::Table, origin: &str) -> Result<Decompiler, ConfigError> {
        let invalid = |key: &str, value: &toml::Value, expected: &'static str| ConfigError::Invalid {
            origin: origin.into(),
            key: format!("decompilers.{name}.{key}"),
            text: match value {
                toml::Value::String(s) => s.clone(),
                toml::Value::Integer(n) => n.to_string(),
                toml::Value::Float(x) => x.to_string(),
                toml::Value::Boolean(b) => b.to_string(),
                other => format!("<{}>", other.type_str()),
            },
            expected,
        };
        let command = match table.get("command") {
            Some(command) => Some(command.as_str().filter(|c| !c.is_empty()).ok_or_else(|| invalid("command", command, "a command"))?),
            None if name == BUILT_IN_DECOMPILER => None,
            None => {
                return Err(ConfigError::Invalid {
                    origin: origin.into(),
                    key: format!("decompilers.{name}.command"),
                    text: String::new(),
                    expected: "a command (required but for the built-in dexdec)",
                });
            }
        };
        if command.is_none()
            && let Some(args) = table.get("args")
        {
            return Err(invalid("args", args, "no args without a command (the built-in dexdec takes none)"));
        }
        let mut decompiler = Decompiler::new("");
        decompiler.command = command.map(expand_home);
        for (key, value) in table {
            let strings = || -> Option<Vec<String>> { value.as_array()?.iter().map(|v| v.as_str().map(String::from)).collect() };
            let duration = |expected| {
                let parsed = match value {
                    toml::Value::Integer(n) => u64::try_from(*n).ok().map(Duration::from_secs),
                    toml::Value::String(s) => parse_duration(s, Duration::from_secs(1)),
                    _ => None,
                };
                parsed.ok_or_else(|| invalid(key, value, expected))
            };
            const DURATION: &str = "a duration (60, 30s, 10m; a bare number is seconds)";
            match key.as_str() {
                "command" => {}
                "args" => decompiler.args = strings().ok_or_else(|| invalid(key, value, "an array of strings"))?,
                "env" => {
                    let env = value.as_table().and_then(|t| t.iter().map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect());
                    decompiler.env = env.ok_or_else(|| invalid(key, value, "a table of strings"))?;
                }
                "cwd" => {
                    let cwd = value.as_str().filter(|c| !c.is_empty()).ok_or_else(|| invalid(key, value, "a directory"))?;
                    decompiler.cwd = Some(expand_home(cwd));
                }
                "instances" => {
                    let n = value.as_integer().and_then(|n| usize::try_from(n).ok()).filter(|&n| n > 0);
                    decompiler.instances = n.ok_or_else(|| invalid(key, value, "a number of processes, at least 1"))?;
                }
                "max_concurrency" => {
                    let n = value.as_integer().and_then(|n| u32::try_from(n).ok()).filter(|&n| n > 0);
                    decompiler.max_concurrency = Some(n.ok_or_else(|| invalid(key, value, "a number of requests, at least 1"))?);
                }
                "idle" => decompiler.idle = duration(DURATION)?,
                "timeout" => decompiler.timeout = duration(DURATION)?,
                "startup_timeout" => decompiler.startup_timeout = duration(DURATION)?,
                "inputs" => {
                    let kinds = strings().filter(|kinds| kinds.iter().all(|kind| INPUT_KINDS.contains(&kind.as_str())));
                    decompiler.inputs = kinds.ok_or_else(|| invalid(key, value, "an array of archive, slice"))?;
                }
                "options" => {
                    let options = value.as_table().and_then(|t| serde_json::to_value(t).ok()).and_then(|v| match v {
                        serde_json::Value::Object(map) => Some(map),
                        _ => None,
                    });
                    decompiler.options = options.ok_or_else(|| invalid(key, value, "a table"))?;
                }
                "enabled" => decompiler.enabled = value.as_bool().ok_or_else(|| invalid(key, value, "true or false"))?,
                unknown => {
                    return Err(ConfigError::UnknownKey {
                        origin: origin.into(),
                        key: format!("decompilers.{name}.{unknown}"),
                        known: KEYS.join(", "),
                    });
                }
            }
        }
        Ok(decompiler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;

    fn load(text: &str) -> Result<Config, ConfigError> {
        Config::resolve(Some((Path::new("c.toml"), text)), |_| None, &[])
    }

    #[test]
    fn tables_read_with_defaults_and_pass_options_through() {
        let c = load(
            r#"
            threads = 2
            [decompile]
            default = "jeb"
            fallback = ["dexdec", "jadx"]
            [decompilers.jeb]
            command = "java"
            args = ["-Xmx6g", "-jar", "/opt/jeb-server.jar", "--stdio"]
            env = { JEB_HOME = "/opt/jeb" }
            instances = 2
            max_concurrency = 1
            idle = "5m"
            timeout = 90
            startup_timeout = "1m"
            inputs = ["slice"]
            options = { finally_rebuilder = true, depth = 3 }
            [decompilers.jadx]
            command = "jadx-worker"
            enabled = false
            "#,
        )
        .unwrap();
        assert_eq!(c.decompile_default.value.0, "jeb");
        assert_eq!(c.decompile_fallback.value.0, ["dexdec", "jadx"]);
        let jeb = &c.decompilers["jeb"];
        assert_eq!(jeb.command.as_deref(), Some(Path::new("java")));
        assert_eq!(jeb.args.len(), 4);
        assert_eq!(jeb.env["JEB_HOME"], "/opt/jeb");
        assert_eq!((jeb.instances, jeb.max_concurrency), (2, Some(1)));
        assert_eq!(
            (jeb.idle, jeb.timeout, jeb.startup_timeout),
            (Duration::from_secs(300), Duration::from_secs(90), Duration::from_secs(60))
        );
        assert_eq!(jeb.inputs, ["slice"]);
        assert_eq!(serde_json::Value::Object(jeb.options.clone()), serde_json::json!({"finally_rebuilder": true, "depth": 3}));
        let jadx = &c.decompilers["jadx"];
        assert!(!jadx.enabled);
        assert_eq!((jadx.instances, jadx.timeout, jadx.cwd.as_ref()), (1, Duration::from_secs(60), None));
    }

    #[test]
    fn bad_tables_name_the_key() {
        let cases = [
            ("[decompilers.x]\nargs = []\n", "decompilers.x.command"),
            ("[decompilers.x]\ncommand = \"x\"\ninstances = 0\n", "decompilers.x.instances = \"0\": expected a number of processes"),
            ("[decompilers.x]\ncommand = \"x\"\ntimeout = \"soon\"\n", "decompilers.x.timeout = \"soon\": expected a duration"),
            ("[decompilers.x]\ncommand = \"x\"\ninputs = [\"apk\"]\n", "expected an array of archive, slice"),
            ("[decompilers.x]\ncommand = \"x\"\nmaxConcurrency = 1\n", "unknown setting \"decompilers.x.maxConcurrency\""),
            ("[decompile]\nfallback = [1]\n", "decompile.fallback = \"<array>\": expected an array of strings"),
            ("decompilers = 1\n", "expected a table of [decompilers.NAME] tables"),
            ("[decompilers.dexdec]\nargs = [\"x\"]\n", "decompilers.dexdec.args"),
        ];
        for (text, want) in cases {
            let e = load(text).unwrap_err().to_string();
            assert!(e.starts_with("c.toml: ") && e.contains(want), "{text:?}: {e}");
        }
    }

    #[test]
    fn the_built_in_backend_needs_no_command() {
        let c = load("[decompilers.dexdec]\noptions = { indent = \"  \" }\ninstances = 2\n").unwrap();
        let dexdec = &c.decompilers[BUILT_IN_DECOMPILER];
        assert_eq!((dexdec.command.as_ref(), dexdec.instances), (None, 2));
        assert_eq!(dexdec.options["indent"], "  ");
    }

    #[test]
    fn decompile_settings_come_from_any_layer() {
        let c = Config::resolve(None, |_| None, &[]).unwrap();
        assert_eq!((c.decompile_default.value.0.as_str(), c.decompile_fallback.value.0.len()), ("dexdec", 0));
        assert_eq!(c.decompile_mapping.value.0, None);
        let env = |name: &str| (name == "ASC_DECOMPILE_FALLBACK").then(|| "jadx, jeb".to_string());
        let flags = [("decompile.mapping".to_string(), "/m/mapping.txt".to_string())];
        let c = Config::resolve(None, env, &flags).unwrap();
        assert_eq!(c.decompile_fallback.value.0, ["jadx", "jeb"]);
        assert_eq!(c.decompile_mapping.value.0.as_deref(), Some(Path::new("/m/mapping.txt")));
        let c = load("[decompile]\nfallback = []\n").unwrap();
        assert!(c.decompile_fallback.value.0.is_empty());
    }
}
