//! Which backends `asc decompile` may use and how each one runs: the
//! `[decompile]` settings and `[decompilers.<name>]` tables of the config
//! file, plus the built-in dexdec and arkdec (docs/decompile-backends.md
//! §4, §9, §12). DEX programs and HarmonyOS programs have a chain each.

use asc_decompile::BackendSpec;
use asc_decompile::protocol::methods::InputKind;
use asc_engine::asc_cache::DECOMPILERS_DIR;
use asc_engine::config::{ARKDEC_DECOMPILER, Config, Decompiler};
use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};

use super::worker::{ARKDEC, DEXDEC, Tool, WorkerSettings};
use crate::format::ProgramFormat;

/// Name of the built-in backend, the default one.
pub const BUILT_IN: &str = asc_engine::config::BUILT_IN_DECOMPILER;

/// Name of the built-in HarmonyOS backend, the default one for HarmonyOS programs.
pub const BUILT_IN_ARKDEC: &str = ARKDEC_DECOMPILER;

/// Where a backend's definition comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// A built-in backend: its worker (`asc-dexdec-worker`,
    /// `asc-arkdec-worker`), wherever asc finds it.
    BuiltIn,
    /// A `[decompilers.<name>]` table of the config file.
    File,
}

impl Origin {
    /// `built-in` or `file`, as `asc config` shows it.
    pub fn name(self) -> &'static str {
        match self {
            Origin::BuiltIn => "built-in",
            Origin::File => "file",
        }
    }
}

/// One backend asc may start.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BackendEntry {
    /// How its processes start and live.
    pub spec: BackendSpec,
    /// The input kinds asc may hand it; empty: whatever it declares.
    pub inputs: Vec<InputKind>,
    /// `false`: configured but never started.
    pub enabled: bool,
    /// Built in or configured.
    pub origin: Origin,
    /// The command is the worker of [`tool`](Self::tool) as asc finds it
    /// (and installs it, when it is released), not one the config file
    /// names: a built-in backend, also when a `[decompilers.dexdec]` /
    /// `[decompilers.arkdec]` table without `command` changes its other keys.
    pub finds_worker: bool,
    /// The worker asc finds for it, when [`finds_worker`](Self::finds_worker).
    pub tool: &'static Tool,
}

impl BackendEntry {
    /// The entry of a `[decompilers.<name>]` table; `cache_dir` holds the
    /// default working directory (`decompilers/<name>/`).
    pub fn from_config(name: &str, table: &Decompiler, cache_dir: Option<&Path>) -> BackendEntry {
        let cwd = table.cwd.clone().or_else(|| cache_dir.map(|dir| dir.join(DECOMPILERS_DIR).join(name)));
        // No command: the built-in worker with the table's other keys.
        let tool = Tool::of_backend(name);
        let (command, args) = match &table.command {
            Some(command) => (command.clone(), table.args.iter().map(Into::into).collect()),
            None => (PathBuf::from(tool.file), Vec::new()),
        };
        let spec = BackendSpec::new(command)
            .args(args)
            .env(table.env.iter().map(|(k, v)| (k.into(), v.into())).collect())
            .cwd(cwd)
            .instances(NonZeroUsize::new(table.instances).unwrap_or(NonZeroUsize::MIN))
            .max_concurrency(table.max_concurrency.and_then(NonZeroU32::new))
            .idle(table.idle)
            .timeout(table.timeout)
            .startup_timeout(table.startup_timeout)
            .options(table.options.clone());
        let inputs = table
            .inputs
            .iter()
            .filter_map(|kind| match kind.as_str() {
                "archive" => Some(InputKind::Archive),
                "slice" => Some(InputKind::Slice),
                "abc" => Some(InputKind::Abc),
                _ => None,
            })
            .collect();
        // The built-in worker takes what it always took, unless the table says otherwise.
        let inputs = if table.command.is_none() && table.inputs.is_empty() { built_in_inputs(tool) } else { inputs };
        BackendEntry { spec, inputs, enabled: table.enabled, origin: Origin::File, finds_worker: table.command.is_none(), tool }
    }

    /// The built-in dexdec: `asc-dexdec-worker` (as a bare name until
    /// [`Settings`] finds it), on the original program files.
    pub fn built_in() -> BackendEntry {
        BackendEntry::built_in_for(&DEXDEC)
    }

    /// The built-in backend of `tool`: dexdec on the original program
    /// files, arkdec on ABC files.
    pub fn built_in_for(tool: &'static Tool) -> BackendEntry {
        let spec = BackendSpec::new(tool.file);
        BackendEntry { spec, inputs: built_in_inputs(tool), enabled: true, origin: Origin::BuiltIn, finds_worker: true, tool }
    }

    /// Whether asc may hand the backend inputs of `kind` (the backend must declare it too).
    pub fn allows(&self, kind: InputKind) -> bool {
        self.inputs.is_empty() || self.inputs.contains(&kind)
    }

    /// The command line, for `asc config` and error messages.
    pub fn command_line(&self) -> String {
        std::iter::once(self.spec.command.as_os_str())
            .chain(self.spec.args.iter().map(|arg| arg.as_os_str()))
            .map(|part| part.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The backends and the choice between them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Settings {
    /// `decompile.default`: used unless a request names a backend.
    pub default: String,
    /// `decompile.fallback`: tried in order when the default fails on a whole class.
    pub fallback: Vec<String>,
    /// `decompile.harmony_default`: used for a HarmonyOS program unless a request names a backend.
    pub harmony_default: String,
    /// `decompile.harmony_fallback`: tried in order when it fails on a whole record.
    pub harmony_fallback: Vec<String>,
    /// `decompile.mapping`: the mapping file whose names source shows.
    pub mapping: Option<PathBuf>,
    /// Every backend by name: the built-in dexdec and arkdec and the
    /// configured ones (a `[decompilers.dexdec]` table replaces the
    /// built-in one, and so for arkdec).
    pub backends: BTreeMap<String, BackendEntry>,
    /// How the worker of the built-in dexdec is found and installed.
    pub dexdec: WorkerSettings,
    /// How the worker of arkdec is found (it is never installed).
    pub arkdec: WorkerSettings,
}

impl Settings {
    /// Only the built-in dexdec and arkdec, no fallback, no mapping file.
    pub fn built_in() -> Settings {
        let mut settings = Settings {
            default: BUILT_IN.to_string(),
            fallback: Vec::new(),
            harmony_default: BUILT_IN_ARKDEC.to_string(),
            harmony_fallback: Vec::new(),
            mapping: None,
            backends: BTreeMap::from([
                (BUILT_IN.to_string(), BackendEntry::built_in()),
                (BUILT_IN_ARKDEC.to_string(), BackendEntry::built_in_for(&ARKDEC)),
            ]),
            dexdec: WorkerSettings::default(),
            arkdec: WorkerSettings { tool: &ARKDEC, ..WorkerSettings::default() },
        };
        settings.locate_worker();
        settings
    }

    /// The settings `config` makes.
    pub fn from_config(config: &Config) -> Settings {
        let cache_dir = config.cache_dir();
        let mut settings = Settings::built_in();
        settings.default = config.decompile_default.value.0.clone();
        settings.fallback = config.decompile_fallback.value.0.clone();
        settings.harmony_default = config.decompile_harmony_default.value.0.clone();
        settings.harmony_fallback = config.decompile_harmony_fallback.value.0.clone();
        settings.mapping = config.decompile_mapping.value.0.clone();
        settings.dexdec = WorkerSettings::for_tool(&DEXDEC, config);
        settings.arkdec = WorkerSettings::for_tool(&ARKDEC, config);
        for (name, table) in &config.decompilers {
            settings.backends.insert(name.clone(), BackendEntry::from_config(name, table, cache_dir.as_deref()));
        }
        settings.locate_worker();
        settings
    }

    /// How the worker of `tool` is found and installed.
    pub fn worker(&self, tool: &Tool) -> &WorkerSettings {
        if tool == &ARKDEC { &self.arkdec } else { &self.dexdec }
    }

    /// Points the entries that run a worker at the one found now, so
    /// `asc config` shows it; requests look again ([`super::Decompilers`]).
    fn locate_worker(&mut self) {
        for tool in [&DEXDEC, &ARKDEC] {
            let Some(worker) = self.worker(tool).locate() else { continue };
            for entry in self.backends.values_mut().filter(|entry| entry.finds_worker && entry.tool == tool) {
                entry.spec.command.clone_from(&worker.path);
            }
        }
    }

    /// The backends a request on a DEX program tries, in order: `chosen`
    /// alone when the request names one, else the default and then the
    /// fallbacks, each once.
    pub fn chain<'a>(&'a self, chosen: Option<&'a str>) -> Vec<&'a str> {
        self.chain_for(ProgramFormat::Android, chosen)
    }

    /// The backends a request on a program of `format` tries, in order:
    /// `chosen` alone when the request names one, else that format's
    /// default and then its fallbacks, each once.
    pub fn chain_for<'a>(&'a self, format: ProgramFormat, chosen: Option<&'a str>) -> Vec<&'a str> {
        let mut chain: Vec<&str> = Vec::new();
        let (default, fallback) = match format {
            ProgramFormat::Android => (&self.default, &self.fallback),
            ProgramFormat::Harmony => (&self.harmony_default, &self.harmony_fallback),
        };
        let names = match chosen {
            Some(name) => vec![name],
            None => std::iter::once(default.as_str()).chain(fallback.iter().map(String::as_str)).collect(),
        };
        for name in names {
            if !chain.contains(&name) {
                chain.push(name);
            }
        }
        chain
    }

    /// Installs a worker now if a request on a program of `format` naming
    /// `chosen` (`None`: the default chain) would, so that its progress and
    /// failure show here: a command about to go to the daemon, whose stderr
    /// nobody reads. A worker that is not released is not installed.
    pub fn prepare_worker(&self, chosen: Option<&str>, format: ProgramFormat) {
        let chain = self.chain_for(format, chosen);
        let mut tools: Vec<&'static Tool> = Vec::new();
        for entry in chain.iter().filter_map(|name| self.backends.get(*name)).filter(|e| e.enabled && e.finds_worker) {
            if !tools.contains(&entry.tool) {
                tools.push(entry.tool);
            }
        }
        for tool in tools {
            let worker = self.worker(tool);
            let worth_trying = worker.auto_install_blocker().is_none() && worker.recent_failure().is_none();
            if worth_trying
                && worker.locate().is_none()
                && let Err(reason) = worker.auto_install()
            {
                eprintln!("asc: {reason}");
            }
        }
    }

    /// The names of the backends, comma separated.
    pub fn known(&self) -> String {
        self.backends.keys().map(String::as_str).collect::<Vec<_>>().join(", ")
    }
}

/// What a built-in backend takes without an `inputs` key: dexdec the
/// original program, arkdec ABC files.
fn built_in_inputs(tool: &Tool) -> Vec<InputKind> {
    if tool == &ARKDEC { vec![InputKind::Abc] } else { vec![InputKind::Archive] }
}

impl Default for Settings {
    fn default() -> Settings {
        Settings::built_in()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        Config::resolve(Some((Path::new("c.toml"), text)), |_| None, &[("cache.dir".into(), "/c".into())]).unwrap()
    }

    #[test]
    fn nothing_configured_means_the_built_in_dexdec() {
        let settings = Settings::from_config(&config(""));
        assert_eq!(settings.default, BUILT_IN);
        assert_eq!(settings.chain(None), [BUILT_IN]);
        let dexdec = &settings.backends[BUILT_IN];
        assert_eq!(dexdec.origin, Origin::BuiltIn);
        assert!(dexdec.finds_worker && dexdec.spec.command.ends_with(DEXDEC.file), "{:?}", dexdec.spec.command);
        assert!(dexdec.spec.args.is_empty());
        assert!(dexdec.allows(InputKind::Archive) && !dexdec.allows(InputKind::Slice));
    }

    #[test]
    fn tables_become_specs_and_the_chain_follows_default_and_fallback() {
        let settings = Settings::from_config(&config(
            "[decompile]\ndefault = \"jeb\"\nfallback = [\"dexdec\", \"jeb\", \"jadx\"]\n\
             [decompilers.jeb]\ncommand = \"java\"\nargs = [\"-jar\", \"jeb.jar\"]\ninstances = 2\nmax_concurrency = 1\ntimeout = \"90s\"\n\
             [decompilers.jadx]\ncommand = \"jadx-worker\"\ncwd = \"/w\"\n",
        ));
        assert_eq!(settings.chain(None), ["jeb", "dexdec", "jadx"], "each backend once, default first");
        assert_eq!(settings.chain(Some("jadx")), ["jadx"], "a named backend has no fallback");
        assert_eq!(settings.known(), "arkdec, dexdec, jadx, jeb");
        let jeb = &settings.backends["jeb"];
        assert_eq!(jeb.command_line(), "java -jar jeb.jar");
        assert_eq!((jeb.spec.instances.get(), jeb.spec.max_concurrency.map(NonZeroU32::get)), (2, Some(1)));
        assert_eq!(jeb.spec.timeout, std::time::Duration::from_secs(90));
        assert_eq!(jeb.spec.cwd.as_deref(), Some(Path::new("/c/decompilers/jeb")), "default cwd under the cache");
        assert_eq!(settings.backends["jadx"].spec.cwd.as_deref(), Some(Path::new("/w")));
        assert!(jeb.allows(InputKind::Slice), "no inputs key: whatever the backend declares");
    }

    #[test]
    fn a_table_named_dexdec_replaces_the_built_in_one() {
        let settings = Settings::from_config(&config("[decompilers.dexdec]\ncommand = \"/opt/dexdec\"\nargs = [\"--stdio\"]\n"));
        let dexdec = &settings.backends[BUILT_IN];
        assert_eq!((dexdec.origin, dexdec.command_line().as_str()), (Origin::File, "/opt/dexdec --stdio"));
        assert!(!dexdec.finds_worker);
        // Without a command it stays the worker asc finds, with the table's other keys.
        let settings = Settings::from_config(&config("[decompilers.dexdec]\ntimeout = 5\noptions = { indent = \"  \" }\n"));
        let dexdec = &settings.backends[BUILT_IN];
        assert!(dexdec.finds_worker && dexdec.spec.command.ends_with(DEXDEC.file) && dexdec.spec.args.is_empty());
        assert_eq!((dexdec.spec.timeout, dexdec.spec.options["indent"].as_str()), (std::time::Duration::from_secs(5), Some("  ")));
        assert!(dexdec.allows(InputKind::Archive) && !dexdec.allows(InputKind::Slice));
    }

    #[test]
    fn harmony_chain_defaults_to_arkdec() {
        let settings = Settings::from_config(&config("[decompile]\ndefault = \"jadx\"\nfallback = [\"dexdec\"]\n"));
        assert_eq!(settings.chain_for(ProgramFormat::Harmony, None), [BUILT_IN_ARKDEC], "the DEX chain is not the HarmonyOS one");
        assert_eq!(settings.chain_for(ProgramFormat::Android, None), ["jadx", "dexdec"]);
        assert_eq!(settings.chain_for(ProgramFormat::Harmony, Some("mock")), ["mock"]);
        let arkdec = &settings.backends[BUILT_IN_ARKDEC];
        assert_eq!((arkdec.origin, arkdec.tool), (Origin::BuiltIn, &ARKDEC));
        assert!(arkdec.finds_worker && arkdec.allows(InputKind::Abc) && !arkdec.allows(InputKind::Archive));
        let settings = Settings::from_config(&config(
            "[decompile]\nharmony_default = \"mock\"\nharmony_fallback = [\"arkdec\", \"mock\"]\n[decompilers.mock]\ncommand = \"m\"\n",
        ));
        assert_eq!(settings.chain_for(ProgramFormat::Harmony, None), ["mock", "arkdec"]);
        assert_eq!(settings.chain(None), [BUILT_IN]);
    }

    #[test]
    fn arkdec_table_without_command_finds_the_worker() {
        let settings = Settings::from_config(&config("[decompilers.arkdec]\ntimeout = 7\noptions = { threads = 2 }\n"));
        let arkdec = &settings.backends[BUILT_IN_ARKDEC];
        assert!(arkdec.finds_worker && arkdec.spec.command.ends_with(ARKDEC.file), "{:?}", arkdec.spec.command);
        assert_eq!((arkdec.origin, arkdec.tool, arkdec.spec.timeout), (Origin::File, &ARKDEC, std::time::Duration::from_secs(7)));
        assert!(arkdec.allows(InputKind::Abc) && !arkdec.allows(InputKind::Archive));
        assert_eq!(settings.worker(&ARKDEC).tool, &ARKDEC);
        let settings = Settings::from_config(&config("[decompilers.arkdec]\ncommand = \"/opt/arkdec\"\n"));
        let arkdec = &settings.backends[BUILT_IN_ARKDEC];
        assert!(!arkdec.finds_worker && arkdec.allows(InputKind::Abc) && arkdec.allows(InputKind::Archive), "a command: what it declares");
    }
}
