//! `droidasc` command line entry.

#[cfg(unix)]
mod daemon;
mod output;
mod settings;

use asc_engine::asc_cache::{DiskCache, DiskCapacity};
use asc_engine::config::Config;
use asc_engine::{names, CacheConfig, CallQuery, CallRoots, Device, Direction, Engine, FindOptions, HierarchyQuery, Lineage, RefContext};
use asc_findrefs::Query;
use clap::{Args, Parser, Subcommand, ValueEnum};
use output::{Io, LocalEngines, SpillTarget, Window};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const EXAMPLES: &str = "global options (accepted by every command, after it too):
  --set KEY=VALUE     any setting of `droidasc config` (repeatable), e.g. --set memory.max=4G
  --threads N         = --set threads=N
  --no-cache          = --set cache.enabled=off
  --cache-dir DIR     = --set cache.dir=DIR
  --cache-max-mb MIB  = --set cache.max=MIB
  --memory-mb MIB     = --set memory.max=MIB (mcp and the daemon; one-shot commands keep none)
  --debug             timing and cache statistics on stderr

settings:
  Threads, memory and disk cache budgets are settings: a flag beats $DROIDASC_<KEY>, which
  beats ~/.config/droidasc/config.toml ($DROIDASC_CONFIG), which beats the default; the
  automatic defaults follow this machine. `droidasc config` lists them with their values
  and sources (--json for scripts).

common:
  Class names accept both com.poc.Main and Lcom/poc/Main;.
  Commands with -o/--output write to stdout when the option is omitted.
  Output is one record per line, columns separated by ` | `; lines starting with `#`
  are headers, totals and hints. --limit / --max-bytes keep stdout short: the whole
  output then goes to a file the last line names, and --offset shows the next records.

examples:
  droidasc getclass app.apk 'Lcom/poc/Main;' -o Main.smali
  droidasc getclass app.apk com.poc.Main --threads 16
  droidasc getclass app.apk com.poc.Main --dump-dex Main.dex
  droidasc disassemble app.apk com.poc.Main --debuginfo
  droidasc disassemble app.apk com.poc.Main --method 'run(I)V'
  droidasc getclass app.apk com.poc.Main --res-names
  droidasc listclass app.apk -o classes.txt
  droidasc listclass app.apk --prefix com.poc
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc getmanifest app.apk --resolve
  droidasc manifest-summary app.apk | grep exported=true
  droidasc manifest-summary app.apk --json
  droidasc resources app.apk string/app_name
  droidasc resources app.apk 0x7f0d0001 --resolve
  droidasc resources app.apk --search 'https?://' --in value
  droidasc resources app.apk -o resources.txt
  droidasc xml app.apk res/xml/network_security_config.xml
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk string 'a.b(c)' --literal
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk extends android.app.Activity -o subclasses.txt
  droidasc findrefs app.apk impl android.os.IInterface
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk method run --class com.poc.Main --exact
  droidasc findrefs app.apk field apiKey -o field_refs.txt
  droidasc findrefs app.apk string token --no-cache
  droidasc findrefs app.apk string token --context 3
  droidasc findrefs app.apk method loadUrl --context-method
  droidasc findrefs app.apk method '{literal:device_id}'
  droidasc findrefs app.apk rules 'method:{string:^https?://} & !type:Lcom/a/test/'
  droidasc findrefs app.apk method @methods.txt
  droidasc callgraph app.apk com.poc.Main onCreate --depth 3
  droidasc callgraph app.apk com.poc.Main 'run(I)V' --callees
  droidasc callgraph app.apk --to 'method:java.lang.Runtime->exec' --from 'method:Intent.getStringExtra' --depth 5
  droidasc mcp --memory-mb 4096
  droidasc cache stats
  droidasc daemon status

exit status:
  0  success
  1  error (bad arguments, unreadable APK, class not found, output not writable, ...)
  2  findrefs / callgraph finished, but one or more DEX entries could not be searched (details on stderr)

Debug output (--debug) goes to stderr so stdout can be redirected.
On Unix, commands answer through a per-user daemon that keeps APKs resident (same output);
DROIDASC_DAEMON=off runs each command in its own process.";

const EXIT_OK: u8 = 0;
/// `resources --search` rows printed without --limit / --max-bytes.
const RESOURCE_SEARCH_ROWS: usize = 1000;
/// Exit status when `findrefs` skipped at least one DEX entry.
const EXIT_PARTIAL: u8 = 2;

#[derive(Parser)]
#[command(name = "droidasc", about = "Search and disassemble APK code without preprocessing.", after_help = EXAMPLES, version, disable_version_flag = true)]
struct Cli {
    /// Print version.
    #[arg(short = 'V', visible_short_alias = 'v', long, action = clap::ArgAction::Version)]
    version: Option<bool>,
    #[command(flatten)]
    common: Common,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct Common {
    /// Enable debug profiling output (written to stderr).
    #[arg(long, global = true, hide = true)]
    debug: bool,
    /// Set any setting of `droidasc config` (repeatable).
    #[arg(long = "set", global = true, value_name = "KEY=VALUE", hide = true)]
    set: Vec<String>,
    /// Worker thread count (`--set threads=N`).
    #[arg(long, alias = "thread", global = true, value_name = "N", hide = true)]
    threads: Option<usize>,
    /// Do not read or write the on-disk cache (`--set cache.enabled=off`).
    #[arg(long, global = true, hide = true)]
    no_cache: bool,
    /// Cache directory (`--set cache.dir=DIR`).
    #[arg(long, global = true, value_name = "DIR", hide = true)]
    cache_dir: Option<PathBuf>,
    /// On-disk cache budget, in MiB (`--set cache.max=MIB`).
    #[arg(long, global = true, value_name = "MIB", hide = true)]
    cache_max_mb: Option<u64>,
    /// In-memory cache budget of `mcp` and the daemon, in MiB (`--set memory.max=MIB`).
    #[arg(long, global = true, value_name = "MIB", hide = true)]
    memory_mb: Option<u64>,
    /// Show at most N records on stdout (results, rows, classes, smali
    /// lines); the whole output goes to a file named on the last line
    /// (default: $DROIDASC_LIMIT, else no limit).
    #[arg(long, global = true, value_name = "N", help_heading = "Output")]
    limit: Option<usize>,
    /// Show at most N bytes of records on stdout, whole records only, the
    /// rest as with --limit (default: $DROIDASC_MAX_BYTES, else no limit).
    #[arg(long, global = true, value_name = "N", help_heading = "Output")]
    max_bytes: Option<usize>,
    /// Skip the first N records (the next page after a cut output).
    #[arg(long, global = true, value_name = "N", default_value_t = 0, help_heading = "Output")]
    offset: usize,
    /// Disk budget of the directory cut outputs (and `mcp` replies over their
    /// budget) are written to, `out/` in the cache directory; 0 writes none
    /// (`--set cache.spill=MIB`, default 64).
    #[arg(long, global = true, value_name = "MIB", help_heading = "Output")]
    spill_mb: Option<u64>,
    /// The settings these flags, the environment and the config file make
    /// ([`Common::resolve`]).
    #[arg(skip)]
    config: Option<Config>,
}

impl Common {
    /// Read the settings: the flags above, then the environment and the
    /// config file. Every command needs them; `main` calls this first.
    fn resolve(&mut self) -> Result<(), String> {
        let mut flags: Vec<(String, String)> = Vec::new();
        let mut flag = |key: &str, value: String| flags.push((key.into(), value));
        if let Some(n) = self.threads {
            flag("threads", n.to_string());
        }
        if self.no_cache {
            flag("cache.enabled", "off".into());
        }
        if let Some(d) = &self.cache_dir {
            // Absolute, so a daemon started from here (in `/`) uses the same one.
            let d = std::env::current_dir().map(|cwd| cwd.join(d)).unwrap_or_else(|_| d.clone());
            flag("cache.dir", d.display().to_string());
        }
        if let Some(mb) = self.cache_max_mb {
            flag("cache.max", mb.to_string());
        }
        if let Some(mb) = self.memory_mb {
            flag("memory.max", mb.to_string());
        }
        if let Some(mb) = self.spill_mb {
            flag("cache.spill", mb.to_string());
        }
        for pair in &self.set {
            let Some((key, value)) = pair.split_once('=') else {
                return Err(format!("--set {pair:?}: expected KEY=VALUE, e.g. --set memory.max=4G (keys: droidasc config)"));
            };
            flag(key.trim(), value.trim().to_string());
        }
        self.config = Some(Config::load(&flags).map_err(|e| format!("{e} (droidasc config lists the settings)"))?);
        Ok(())
    }

    fn config(&self) -> &Config {
        self.config.as_ref().expect("Common::resolve runs before any command")
    }

    /// The engine every subcommand uses: shared flags, disk cache unless
    /// disabled, and log lines on stderr so stdout stays clean for redirection.
    fn engine(&self, apk_path: &Path) -> Engine {
        let config = self.config();
        let mut engine = Engine::new(apk_path).with_debug(self.debug).with_threads(config.threads()).with_logger(|m| eprintln!("{m}"));
        if config.cache_enabled.value {
            engine = engine.with_cache(config.one_shot_cache());
        }
        engine
    }

    fn disk_cache(&self) -> Option<DiskCache> {
        self.config().disk_cache()
    }

    /// `--offset` / `--limit` / `--max-bytes`, the last two defaulting to
    /// `$DROIDASC_LIMIT` / `$DROIDASC_MAX_BYTES` so an agent host can set them
    /// once.
    fn window(&self) -> Window {
        let env = |name: &str| std::env::var(name).ok().and_then(|v| v.trim().parse().ok());
        Window {
            offset: self.offset,
            limit: self.limit.or_else(|| env("DROIDASC_LIMIT")),
            max_bytes: self.max_bytes.or_else(|| env("DROIDASC_MAX_BYTES")),
        }
    }

    /// Where a cut output is written: `out/` in the cache directory (else a
    /// per-user runtime directory); `None` with `--spill-mb 0`.
    fn spill(&self) -> Option<SpillTarget> {
        let config = self.config();
        let bytes = config.cache_spill.value.0;
        (bytes > 0).then(|| SpillTarget { dir: asc_mcp::output::SpillDir::default_dir(config.cache_dir().as_deref()), bytes })
    }

    /// Cache of the resident hosts (`mcp`, the daemon): the memory budget
    /// (following this machine unless fixed) plus the disk cache.
    fn resident_cache(&self) -> CacheConfig {
        self.config().resident_cache(&Device::probe())
    }
}

#[derive(Subcommand)]
enum Command {
    /// Locate the target class in APK, extract one DEX in memory, then disassemble.
    Getclass {
        /// Also write the output to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Do not emit .line / .param debug directives.
        #[arg(long)]
        no_debug_info: bool,
        /// Write the rebuilt single-class DEX to this file.
        #[arg(long)]
        dump_dex: Option<PathBuf>,
        /// Render only these methods (no fields): a name (every overload) or a
        /// signature, e.g. run or run(I)V.
        #[arg(long = "method", value_name = "NAME|SIGNATURE")]
        method_signature: Option<String>,
        /// Append `# @type/name` to constants that are resource ids (from resources.arsc).
        #[arg(long)]
        res_names: bool,
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// The Dalvik format class name to extract (e.g., Lcom/poc/Main; or com.poc.Main).
        dalvik_class: String,
    },
    /// Extract a class, rebuild a small DEX, then disassemble it (getclass without debug directives by default).
    Disassemble {
        /// Write disassembly to this file; default is stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Include DEX .line and .param debug directives.
        #[arg(long)]
        debuginfo: bool,
        /// Render only these methods (no fields): a name (every overload) or a
        /// signature, e.g. run or run(I)V.
        #[arg(long = "method", value_name = "NAME|SIGNATURE")]
        method_signature: Option<String>,
        /// Append `# @type/name` to constants that are resource ids (from resources.arsc).
        #[arg(long)]
        res_names: bool,
        /// Write the rebuilt single-class DEX to this file.
        #[arg(long)]
        dump_dex: Option<PathBuf>,
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// Class name in dotted or Dalvik form, e.g. com.poc.Main or Lcom/poc/Main;.
        dalvik_class: String,
    },
    /// List classes across all DEX entries; use --prefix to filter by package/class prefix.
    #[command(visible_alias = "classes")]
    Listclass {
        /// Only list classes with this package/class prefix (e.g., com.poc or Lcom/poc).
        #[arg(long)]
        prefix: Option<String>,
        /// Write class names to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Path to the input APK file.
        apk_path: PathBuf,
    },
    /// Decode AndroidManifest.xml from APK and print it as XML.
    #[command(visible_alias = "manifest")]
    Getmanifest {
        /// Also write the decoded manifest to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Show resource references (@7F0C0001) by name, from resources.arsc.
        #[arg(short, long)]
        resolve: bool,
        /// Path to the input APK file.
        apk_path: PathBuf,
    },
    /// Summarize the manifest's attack surface, one record per line:
    /// package, application flags, permissions, components (exported or not,
    /// and why), intent filters, deep links, FileProvider paths, network
    /// security config. References are resolved through resources.arsc.
    #[command(alias = "manifest_summary")]
    ManifestSummary {
        /// Print JSON instead of lines.
        #[arg(long)]
        json: bool,
        /// Also write the output to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Path to the input APK file.
        apk_path: PathBuf,
    },
    /// Query resources.arsc: one line per resource and configuration,
    /// `0x7f0d0001 string/app_name [zh-rCN] "value"`.
    ///
    /// With no QUERY and no --search, dumps the whole table.
    Resources {
        /// Search names and string values with this regex.
        #[arg(long, value_name = "REGEX", conflicts_with = "query")]
        search: Option<String>,
        /// Match --search as a plain substring.
        #[arg(long, requires = "search")]
        literal: bool,
        /// What --search matches: name, value or any.
        #[arg(long = "in", value_name = "FIELD", default_value = "any", requires = "search")]
        field: String,
        /// Follow QUERY's reference chain to its final value.
        #[arg(long, requires = "query")]
        resolve: bool,
        /// Write the output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// A resource id (0x7f0d0001) or name (string/app_name, @pkg:type/name).
        query: Option<String>,
    },
    /// Decode any binary XML file of the APK (res/xml/..., layouts) with
    /// resource references shown by name.
    Xml {
        /// Also write the decoded XML to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// Path inside the APK, e.g. res/xml/network_security_config.xml.
        path: String,
    },
    /// Find code references for string/type/method/field across all DEX entries in APK.
    ///
    /// Exits with status 2 when some DEX entries could not be searched; the
    /// results of the other entries are still printed.
    Findrefs {
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// After each result, show the referencing instructions (marked `>`)
        /// with N smali lines around them, and their pc / source line; or
        /// `method` for the whole referencing method.
        #[arg(long, global = true, value_name = "N|method", value_parser = parse_context, conflicts_with = "context_method")]
        context: Option<RefContext>,
        /// Same as `--context method`.
        #[arg(long, global = true, hide = true)]
        context_method: bool,
        #[command(subcommand)]
        find: Find,
    },
    /// Callers (default) or callees of a method, as an indented tree, across all DEX entries.
    ///
    /// One line per call: depth, `<-` (caller) or `->` (callee), signature.
    /// `[no body]` marks methods no DEX of the APK defines (framework / SDK),
    /// `(repeated)` methods expanded elsewhere in the tree. References are
    /// static: a call through a subclass is not a call of the base method
    /// (unless --virtual).
    ///
    /// The target is CLASS METHOD, or every method whose code matches a
    /// findrefs rule (--to; --from alone walks callees). --to with --from
    /// keeps only the caller paths that start at a --from method (marked
    /// `[from]`); --unless leaves out methods whose code matches a rule.
    Callgraph {
        /// Write the tree to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Walk callees instead of callers.
        #[arg(long)]
        callees: bool,
        /// Levels to expand.
        #[arg(long, default_value_t = 2)]
        depth: usize,
        /// Stop after discovering this many methods.
        #[arg(long, value_name = "N", default_value_t = 500)]
        max_nodes: usize,
        /// Follow virtual dispatch: callers also through the same signature on
        /// each supertype (`(via Lbase;)`), callees also the overrides in
        /// subclasses (`(override of Lbase;)`).
        #[arg(long = "virtual")]
        virtual_calls: bool,
        /// Target: every method whose code matches this findrefs rule, e.g.
        /// 'method:android.telephony.TelephonyManager->getImei'.
        #[arg(long, value_name = "RULE")]
        to: Option<String>,
        /// Keep the caller paths that start at a method whose code matches
        /// this rule; without a target, walk the callees of those methods.
        #[arg(long, value_name = "RULE")]
        from: Option<String>,
        /// Leave out every method whose code matches this rule, and what is
        /// reached only through it (repeatable).
        #[arg(long, value_name = "RULE")]
        unless: Vec<String>,
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// Declaring class (com.poc.Main or Lcom/poc/Main;).
        class: Option<String>,
        /// Method name (every overload) or exact signature, e.g. run(I)V.
        #[arg(requires = "class")]
        method: Option<String>,
    },
    /// Class hierarchy across all DEX entries: transitive subclasses and
    /// implementers (default) or supertypes, as an indented tree.
    ///
    /// One line per class: depth, `subclass` / `implementer` (or `extends` /
    /// `implements` with --supers), descriptor, defining DEX or `[not in APK]`.
    /// With --method, classes defining it are marked `[defines m(..)V]` and
    /// listed as `override Lsub;->m(..)V dex` lines (`inherited` with --supers).
    Hierarchy {
        /// Write the tree to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Walk superclasses and interfaces instead of subclasses.
        #[arg(long)]
        supers: bool,
        /// Levels to walk.
        #[arg(long, default_value_t = 16)]
        depth: usize,
        /// Stop after discovering this many classes.
        #[arg(long, value_name = "N", default_value_t = 2000)]
        max_nodes: usize,
        /// Mark the classes defining this method: a name or name(params)ret.
        #[arg(long)]
        method: Option<String>,
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// Class in dotted or Dalvik form.
        class: String,
    },
    /// Serve MCP tools over stdio (one JSON-RPC message per line), keeping
    /// opened APKs resident across calls.
    /// Every opened APK shares one `--memory-mb` budget.
    Mcp {
        /// Refuse a single entry that inflates past this many MiB (zip bombs).
        #[arg(long, default_value_t = 1024)]
        max_entry_mb: u64,
        /// Refuse an entry that expands more than this over its compressed size.
        #[arg(long, default_value_t = 100)]
        max_ratio: u64,
        /// Package prefixes `collapse_sdks` folds, comma separated (com.foo or
        /// Lcom/foo/), replacing the built-in list.
        #[arg(long, value_delimiter = ',')]
        sdk_prefixes: Option<Vec<String>>,
        /// structuredContent: `compact` leaves out its bulky values (rows,
        /// smali) that the text already carries, since some clients show
        /// the model both; `full` keeps everything.
        #[arg(long, value_enum, default_value_t = StructuredArg::Compact)]
        structured: StructuredArg,
    },
    /// Inspect or clear the on-disk cache of inflated DEX files.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// The per-user daemon that keeps APKs resident for one-shot commands.
    ///
    /// Commands start it on first use and answer through it afterwards, with
    /// the same output as without it; it exits after 15 idle minutes.
    /// `DROIDASC_DAEMON=off` runs every command in its own process.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// The settings of threads, memory and the disk cache: values, sources and what `auto` is on this machine.
    Config {
        #[command(subcommand)]
        action: Option<settings::ConfigAction>,
        /// One JSON object (for scripts and agents).
        #[arg(long)]
        json: bool,
    },
}

impl Command {
    /// The APK of a one-shot command (`None` for the resident and
    /// maintenance commands).
    fn apk_path(&self) -> Option<&Path> {
        match self {
            Command::Getclass { apk_path, .. }
            | Command::Disassemble { apk_path, .. }
            | Command::Listclass { apk_path, .. }
            | Command::Getmanifest { apk_path, .. }
            | Command::ManifestSummary { apk_path, .. }
            | Command::Resources { apk_path, .. }
            | Command::Xml { apk_path, .. }
            | Command::Findrefs { apk_path, .. }
            | Command::Callgraph { apk_path, .. }
            | Command::Hierarchy { apk_path, .. } => Some(apk_path),
            Command::Mcp { .. } | Command::Cache { .. } | Command::Daemon { .. } | Command::Config { .. } => None,
        }
    }
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon of this build and cache configuration (if not running).
    Start,
    /// Stop every daemon of this user.
    Stop,
    /// Show the running daemons.
    Status,
    /// Run the daemon in this process (what `start` spawns).
    #[command(hide = true)]
    Serve,
}

/// `--context`: a number of lines, or `method`.
fn parse_context(s: &str) -> Result<RefContext, String> {
    match s.trim() {
        "method" => Ok(RefContext::Method),
        n => n.parse().map(RefContext::Lines).map_err(|_| format!("{s:?} is neither a number of lines nor `method`")),
    }
}

/// `mcp --structured`.
#[derive(Clone, Copy, ValueEnum)]
enum StructuredArg {
    Compact,
    Full,
}

#[derive(Subcommand)]
enum CacheAction {
    /// Print the cache directory.
    Path,
    /// Print how much is cached.
    Stats,
    /// Delete every cached file.
    Clear,
}

#[derive(Subcommand)]
enum Find {
    /// Find references to a fuzzy string (regex).
    String {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Match VALUE as a plain substring instead of a regex.
        #[arg(long)]
        literal: bool,
        /// Fuzzy string pattern.
        value: String,
    },
    /// Find references to a fuzzy type descriptor/name.
    Type {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy type pattern.
        value: String,
    },
    /// Find classes that extend the target class.
    Extends {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Target class in dotted or Dalvik form, e.g. android.app.Activity or Lcom/poc/Base;.
        value: String,
    },
    /// Find classes that implement the target interface.
    Impl {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Target interface in dotted or Dalvik form, e.g. android.os.IInterface.
        value: String,
    },
    /// Find references to methods.
    Method {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy method name, or the whole target: Lcom/a/B;->name,
        /// com.a.B.name, com.a.B#name, B.name (any package); or '{RULE}'
        /// (calls of the methods whose code matches RULE) or @FILE (of the
        /// methods FILE lists).
        name: Option<String>,
        /// Dalvik class or fuzzy class pattern.
        #[arg(long = "class")]
        class_name: Option<String>,
        /// Treat --class as fuzzy match.
        #[arg(long)]
        fuzzy_class: bool,
        /// Match the name exactly instead of as a substring / regex.
        #[arg(long)]
        exact: bool,
    },
    /// Find methods whose code matches every condition (and none of --none),
    /// e.g. `all string:http:// method:android.webkit.WebView->loadUrl`.
    ///
    /// Conditions are KIND:VALUE: string:REGEX, literal:TEXT, type:PATTERN,
    /// method:TARGET, field:TARGET. TARGET is [CLASS->]NAME, also written
    /// com.a.B.name or com.a.B#name (CLASS exact, `~CLASS` fuzzy, without
    /// package any package; NAME a regex / substring, `=NAME` or a name
    /// with its signature exact). method:{RULE} is a call of any method whose
    /// code matches RULE (a rule as for `rules`), method:@FILE of any method
    /// FILE lists (one per line; findrefs output works). `!CONDITION` is
    /// one more --none. The last column lists what each condition matched,
    /// in order.
    All {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Drop methods that also match this condition (repeatable).
        #[arg(long, value_name = "CONDITION")]
        none: Vec<String>,
        /// Conditions that must all match in one method.
        #[arg(required = true)]
        conditions: Vec<String>,
    },
    /// Run several queries in one pass over each DEX, rows prefixed by rule
    /// (`r1 | dex | ...`), after a `# r1 ...` header per rule.
    ///
    /// Each rule is a condition as for `all` (also extends:CLASS,
    /// impl:CLASS), or several joined with `&` for a compound rule, `!`
    /// before the ones a method must not match. `&` inside `{}` or `()`, or
    /// written `\&`, belongs to its condition.
    Rules {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Read more rules from this file, one per line (`#` comments).
        #[arg(long)]
        file: Option<PathBuf>,
        /// The rules.
        rules: Vec<String>,
    },
    /// Find references to fields.
    Field {
        /// Also write every result to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy field name, or the whole target: Lcom/a/B;->name,
        /// com.a.B.name, com.a.B#name, B.name (any package).
        name: Option<String>,
        /// Dalvik class or fuzzy class pattern.
        #[arg(long = "class")]
        class_name: Option<String>,
        /// Treat --class as fuzzy match.
        #[arg(long)]
        fuzzy_class: bool,
        /// Match the name exactly instead of as a substring / regex.
        #[arg(long)]
        exact: bool,
    },
}

/// `findrefs rules`: every rule in one pass, rows prefixed `rN | `.
#[allow(clippy::too_many_arguments)] // one call site, each argument a CLI option
fn findrefs_rules(
    io: &mut Io<'_>,
    common: &Common,
    apk_path: &Path,
    context: RefContext,
    output: Option<PathBuf>,
    file: Option<PathBuf>,
    mut specs: Vec<String>,
    t_start: Instant,
) -> Result<u8, String> {
    if let Some(f) = &file {
        let text = std::fs::read_to_string(io.path(f)).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        specs.extend(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from));
    }
    if specs.is_empty() {
        return Err("findrefs rules needs at least one rule".into());
    }
    let rules = specs.iter().map(|spec| io.rule(spec)).collect::<Result<Vec<_>, _>>()?;
    let engine = io.engine(common, apk_path);
    let cancel = io.cancel;
    let mut order = DexOrder::new(&engine, rules.len())?;
    let mut sink = io.sink(output.as_ref(), true)?;
    for (i, spec) in specs.iter().enumerate() {
        sink.comment(&format!("# r{} {spec}", i + 1));
    }
    let mut errors = Vec::new();
    let mut totals = vec![0usize; rules.len()];
    let opts = FindOptions { aggregate: true, context };
    let mut print = |(i, batch): (usize, asc_engine::RefBatch), sink: &mut output::LineSink<_>| {
        if let Some(e) = batch.error {
            errors.push(format!("{}: {e}", batch.entry_name));
        }
        totals[i] += batch.results.len();
        for r in &batch.results {
            let record: Vec<String> = r
                .text()
                .lines()
                .enumerate()
                .map(|(j, line)| if j == 0 { format!("r{} | {line}", i + 1) } else { format!("r{} |{line}", i + 1) })
                .collect();
            sink.line(&record.join("\n"));
        }
    };
    engine
        .find_refs_rules(&rules, opts, cancel, &mut |i, batch| {
            let name = batch.entry_name.clone();
            for item in order.push(&name, i, (i, batch)) {
                print(item, &mut sink);
            }
            sink.flush_stdout();
        })
        .map_err(|e| e.to_string())?;
    for item in order.finish() {
        print(item, &mut sink);
    }
    for (i, n) in totals.iter().enumerate() {
        sink.comment(&format!("# r{} {n} results", i + 1));
    }
    let io_result = sink.finish();
    errors.sort();
    errors.dedup();
    for e in &errors {
        io.note(format_args!("Warning: {e}"));
    }
    for (i, (n, rule)) in totals.iter().zip(&rules).enumerate() {
        if let Some(h) = (*n == 0).then(|| asc_engine::hints::query_hint(rule)).flatten() {
            io.note(format_args!("hint: r{}: {h}", i + 1));
        }
    }
    if common.debug {
        io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
    }
    io_result?;
    Ok(if errors.is_empty() { EXIT_OK } else { EXIT_PARTIAL })
}

/// A findrefs run's batches in DEX order (`classes.dex`, `classes2.dex`, ...,
/// then other names), whatever order the workers finish in. An entry's
/// batches (one per rule, `parts` in all) wait until every earlier entry is
/// complete, so the output is the same on every run and still streams as
/// soon as the order allows.
struct DexOrder<T> {
    order: Vec<String>,
    next: usize,
    parts: usize,
    pending: HashMap<String, Vec<(usize, T)>>,
}

impl<T> DexOrder<T> {
    fn new(engine: &Engine, parts: usize) -> Result<DexOrder<T>, String> {
        let mut order: Vec<String> = engine.dex_entries().map_err(|e| e.to_string())?.into_iter().map(|e| e.name).collect();
        order.sort_by(|a, b| dex_rank(a).cmp(&dex_rank(b)));
        Ok(DexOrder { order, next: 0, parts, pending: HashMap::new() })
    }

    /// Take `item` (part `part` of `entry`); the items now due, in order.
    fn push(&mut self, entry: &str, part: usize, item: T) -> Vec<T> {
        self.pending.entry(entry.to_string()).or_default().push((part, item));
        let mut due = Vec::new();
        while let Some(name) = self.order.get(self.next) {
            if self.pending.get(name).is_none_or(|items| items.len() < self.parts) {
                break;
            }
            if let Some(items) = self.pending.remove(name) {
                due.extend(by_part(items));
            }
            self.next += 1;
        }
        due
    }

    /// Everything still held (entries a cancelled or replayed run left
    /// incomplete), in order.
    fn finish(mut self) -> Vec<T> {
        let mut names: Vec<String> = self.pending.keys().cloned().collect();
        names.sort_by(|a, b| dex_rank(a).cmp(&dex_rank(b)));
        names.into_iter().filter_map(|n| self.pending.remove(&n)).flat_map(by_part).collect()
    }
}

fn by_part<T>(mut items: Vec<(usize, T)>) -> impl Iterator<Item = T> {
    items.sort_by_key(|(part, _)| *part);
    items.into_iter().map(|(_, item)| item)
}

/// Sort key of a DEX entry name: `classes.dex`, `classes2.dex`, ... by
/// number, then every other name alphabetically.
fn dex_rank(name: &str) -> (u8, u64, &str) {
    match name.strip_prefix("classes").and_then(|rest| rest.strip_suffix(".dex")) {
        Some("") => (0, 1, name),
        Some(n) if !n.starts_with('0') => n.parse().map_or((1, 0, name), |k| (0, k, name)),
        _ => (1, 0, name),
    }
}

/// Arguments shared by `getclass` and `disassemble`, which differ (as in
/// Python) in whether debug directives are on by default and whether `-o`
/// also prints to stdout.
struct ClassArgs {
    output: Option<PathBuf>,
    /// Print to stdout even with `-o`.
    tee: bool,
    debug_info: bool,
    dump_dex: Option<PathBuf>,
    method_signature: Option<String>,
    res_names: bool,
    apk_path: PathBuf,
    dalvik_class: String,
}

/// The class, or only the methods `method` names: an exact signature is
/// rendered on its own; a name, a signature prefix or a Java-style signature
/// is picked from the whole class (as MCP `getclass` does).
fn class_methods(
    engine: &Engine,
    descriptor: &str,
    opts: asc_engine::SmaliOptions,
    method: Option<&str>,
    cancel: &AtomicBool,
) -> Result<asc_engine::ClassSource, String> {
    // `name(params)ret`: what the engine renders on its own.
    let full_signature = |m: &&str| m.split_once(')').is_some_and(|(head, ret)| head.contains('(') && !ret.trim().is_empty());
    if let Some(m) = method.filter(full_signature) {
        if let Ok(src) = engine.get_class_method_cancellable(descriptor, opts, Some(m), cancel) {
            return Ok(src);
        }
    }
    let mut src = engine.get_class_method_cancellable(descriptor, opts, None, cancel).map_err(|e| e.to_string())?;
    if let Some(m) = method {
        let parsed = asc_mcp::class_text::ClassText::parse(&src.source);
        let picked = parsed.select(m);
        if picked.is_empty() {
            return Err(format!("{descriptor} has no method {m:?}; its methods: {}", parsed.signatures(4 << 10)));
        }
        let text = parsed.with_methods(&picked);
        src.source = text;
    }
    Ok(src)
}

fn getclass(io: &mut Io<'_>, common: &Common, args: ClassArgs, t_start: Instant) -> Result<(), String> {
    let descriptor = names::format_class_name(&args.dalvik_class).map_err(|e| e.to_string())?;
    let engine = io.engine(common, &args.apk_path);
    let opts = asc_engine::SmaliOptions { line_numbers: args.debug_info, param_names: args.debug_info };
    let mut src = class_methods(&engine, &descriptor, opts, args.method_signature.as_deref(), io.cancel)?;
    if args.res_names {
        src.source = engine.annotate_resource_ids(&src.source);
    }
    if let Some(w) = &src.warning {
        io.note(format_args!("Warning: {w}"));
    }
    if let Some(p) = &args.dump_dex {
        let rebuilt = src.rebuilt.as_ref().ok_or_else(|| format!("cannot write {}: the class was not rebuilt", p.display()))?;
        io.write_file(p, &rebuilt.bytes)?;
    }
    if common.debug {
        io.note(format_args!("[DEBUG] Hit DEX: {}", src.dex_name));
        io.note(format_args!("[DEBUG] APK Scan Time: {} us", src.scan_us));
        if let Some(r) = &src.rebuilt {
            io.note(format_args!(
                "[DEBUG] Rebuilt DEX: {} bytes, {} strings, {} types, {} protos, {} fields, {} methods ({} with code)",
                r.stats.size, r.stats.strings, r.stats.types, r.stats.protos, r.stats.fields, r.stats.methods, r.stats.methods_with_code
            ));
        }
        io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
        io.note("-".repeat(50));
    }
    io.write_output(args.output.as_ref(), &src.source)?;
    if args.output.is_some() && !args.tee {
        return Ok(());
    }
    io.emit_records(&src.source, args.output.as_ref())
}

/// Run a one-shot command (everything but `mcp`, `cache` and `daemon`,
/// which [`run`] handles itself) against `io`: the exit status.
fn run_query(io: &mut Io<'_>, common: &Common, command: Command, t_start: Instant) -> Result<u8, String> {
    io.window = common.window();
    io.spill = common.spill();
    match command {
        Command::Getclass { output, no_debug_info, dump_dex, method_signature, res_names, apk_path, dalvik_class } => {
            let args =
                ClassArgs { output, tee: true, debug_info: !no_debug_info, dump_dex, method_signature, res_names, apk_path, dalvik_class };
            getclass(io, common, args, t_start)?;
        }
        Command::Disassemble { output, debuginfo, method_signature, res_names, dump_dex, apk_path, dalvik_class } => {
            let args =
                ClassArgs { output, tee: false, debug_info: debuginfo, dump_dex, method_signature, res_names, apk_path, dalvik_class };
            getclass(io, common, args, t_start)?;
        }
        Command::Listclass { prefix, output, apk_path } => {
            let classes = io.engine(common, &apk_path).list_classes(prefix.as_deref()).map_err(|e| e.to_string())?;
            let mut text = String::with_capacity(classes.iter().map(|c| c.descriptor.len() + 1).sum());
            for c in &classes {
                text.push_str(&c.descriptor);
                text.push('\n');
            }
            match &output {
                Some(p) => io.write_file(p, text.as_bytes())?,
                None if text.is_empty() => {}
                None => io.emit_records(&text, None)?,
            }
            if common.debug {
                io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
            }
        }
        Command::Getmanifest { output, resolve, apk_path } => {
            let engine = io.engine(common, &apk_path);
            let xml = if resolve { engine.manifest_xml_resolved() } else { engine.manifest_xml() }.map_err(|e| e.to_string())?;
            io.write_output(output.as_ref(), &xml)?;
            io.emit_records(&xml, output.as_ref())?;
            if common.debug {
                io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
            }
        }
        Command::ManifestSummary { json, output, apk_path } => {
            let summary = io.engine(common, &apk_path).manifest_summary().map_err(|e| e.to_string())?;
            let text = if json { format!("{:#}", summary.json()) } else { summary.lines().join("\n") };
            io.write_output(output.as_ref(), &text)?;
            io.emit_records(&text, output.as_ref())?;
        }
        Command::Resources { search, literal, field, resolve, output, apk_path, query } => {
            let engine = io.engine(common, &apk_path);
            let mut note = None;
            // With a window every match goes through it (the file holds them all).
            let search_cap = if output.is_none() && !io.window.is_everything() { usize::MAX } else { RESOURCE_SEARCH_ROWS };
            let mut sink = io.sink(output.as_ref(), output.is_none())?;
            match (search, query) {
                (Some(pattern), _) => {
                    let field = match field.as_str() {
                        "name" => asc_engine::ResourceField::Name,
                        "value" => asc_engine::ResourceField::Value,
                        "any" => asc_engine::ResourceField::Any,
                        other => return Err(format!("--in must be name, value or any, not {other}")),
                    };
                    let (rows, total) = engine.search_resources(&pattern, literal, field, search_cap).map_err(|e| e.to_string())?;
                    rows.iter().for_each(|r| sink.line(&r.line()));
                    if total > rows.len() {
                        note = Some(format!(
                            "Note: {} of {total} matches shown; with --limit or --max-bytes every match goes to a file",
                            rows.len()
                        ));
                    }
                }
                (None, Some(q)) if resolve => {
                    let (chain, row) = engine.resolve_resource(&q, None).map_err(|e| e.to_string())?;
                    sink.line(&format!("chain {}", chain.join(" -> ")));
                    sink.line(&row.line());
                }
                (None, Some(q)) => engine.resource(&q).map_err(|e| e.to_string())?.iter().for_each(|r| sink.line(&r.line())),
                (None, None) => engine.dump_resources(|r| sink.line(&r.line())).map_err(|e| e.to_string())?,
            }
            let io_result = sink.finish();
            if let Some(n) = note {
                io.note(n);
            }
            io_result?;
        }
        Command::Xml { output, apk_path, path } => {
            let xml = io.engine(common, &apk_path).xml(&path).map_err(|e| e.to_string())?;
            io.write_output(output.as_ref(), &xml)?;
            io.emit_records(&xml, output.as_ref())?;
        }
        Command::Findrefs { apk_path, context, context_method, find } => {
            let context = match (context, context_method) {
                (Some(c), _) => c,
                (None, true) => RefContext::Method,
                (None, false) => RefContext::None,
            };
            if let Find::Rules { output, file, rules } = find {
                return findrefs_rules(io, common, &apk_path, context, output, file, rules, t_start);
            }
            let (query, output) = match find {
                Find::Rules { .. } => unreachable!("handled above"),
                Find::All { output, none, conditions } => {
                    // `!COND` among the conditions is one more --none.
                    let (excluded, conditions): (Vec<String>, Vec<String>) = conditions.into_iter().partition(|c| c.starts_with('!'));
                    let parse =
                        |c: &[String]| c.iter().map(|c| io.condition(c.strip_prefix('!').unwrap_or(c))).collect::<Result<Vec<_>, _>>();
                    let mut all = parse(&conditions)?;
                    let mut none = parse(&none)?;
                    none.extend(parse(&excluded)?);
                    // One condition is that query itself (`all 'method:{...}'`).
                    if all.len() == 1 && none.is_empty() {
                        (all.pop().expect("one condition"), output)
                    } else {
                        (Query::All { all, none }, output)
                    }
                }
                Find::String { output, literal: false, value } => (Query::String(value), output),
                Find::String { output, literal: true, value } => (Query::StringLiteral(value), output),
                Find::Type { output, value } => (Query::Type(value), output),
                // The class-def lookups need the precise Dalvik form.
                Find::Extends { output, value } => (Query::Extends(names::format_class_name(&value).map_err(|e| e.to_string())?), output),
                Find::Impl { output, value } => (Query::Implements(names::format_class_name(&value).map_err(|e| e.to_string())?), output),
                // `method '{RULE}'` / `method @FILE`, as in a condition.
                Find::Method { output, name: Some(name), class_name: None, .. } if name.starts_with(['{', '@']) => {
                    (io.condition(&format!("method:{name}"))?, output)
                }
                Find::Method { output, name, class_name, fuzzy_class, exact } => (
                    Query::Method(
                        names::member_query("method", class_name.as_deref(), fuzzy_class, name.as_deref(), exact)
                            .map_err(|e| e.to_string())?,
                    ),
                    output,
                ),
                Find::Field { output, name, class_name, fuzzy_class, exact } => (
                    Query::Field(
                        names::member_query("field", class_name.as_deref(), fuzzy_class, name.as_deref(), exact)
                            .map_err(|e| e.to_string())?,
                    ),
                    output,
                ),
            };
            let engine = io.engine(common, &apk_path);
            let cancel = io.cancel;
            let mut order = DexOrder::new(&engine, 1)?;
            let mut sink = io.sink(output.as_ref(), true)?;
            let mut errors = Vec::new();
            let opts = FindOptions { aggregate: true, context };
            let mut print = |batch: asc_engine::RefBatch, sink: &mut output::LineSink<_>| {
                if let Some(e) = batch.error {
                    errors.push(format!("{}: {e}", batch.entry_name));
                }
                for r in &batch.results {
                    sink.line(&r.text());
                }
            };
            let summary = engine
                .find_refs_opts(&query, opts, cancel, &mut |batch| {
                    let name = batch.entry_name.clone();
                    for b in order.push(&name, 0, batch) {
                        print(b, &mut sink);
                    }
                    sink.flush_stdout();
                })
                .map_err(|e| e.to_string())?;
            for b in order.finish() {
                print(b, &mut sink);
            }
            let io_result = sink.finish();
            for e in &errors {
                io.note(format_args!("Warning: {e}"));
            }
            if summary.total_results == 0 && errors.is_empty() {
                for h in engine.no_results_hints(&query, summary.entries) {
                    io.note(format_args!("hint: {h}"));
                }
            }
            if common.debug {
                let st = engine.cache_stats();
                io.note(format_args!("[DEBUG] Cache: {} inflated, {} disk hits, {} skipped", st.inflates, st.disk_hits, st.skipped));
                io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
            }
            io_result?;
            if !errors.is_empty() {
                io.note(format_args!(
                    "Warning: {} DEX entr{} could not be searched",
                    errors.len(),
                    if errors.len() == 1 { "y" } else { "ies" }
                ));
                return Ok(EXIT_PARTIAL);
            }
        }
        Command::Callgraph { output, callees, depth, max_nodes, virtual_calls, to, from, unless, apk_path, class, method } => {
            let target = match (class, method, to) {
                (None, None, None) => None,
                (None, None, Some(to)) => Some(CallRoots::Matching(io.rule(&to)?)),
                (Some(class), Some(method), None) => {
                    Some(CallRoots::Method { class: names::format_class_name(&class).map_err(|e| e.to_string())?, method })
                }
                (Some(_), None, None) | (None, Some(_), None) => return Err("callgraph needs the METHOD after the CLASS".into()),
                (_, _, Some(_)) => return Err("give the target as CLASS METHOD or as --to RULE, not both".into()),
            };
            let from = from.map(|f| io.rule(&f)).transpose()?;
            let (roots, direction, from) = match (target, from) {
                (Some(roots), from) => (roots, if callees { Direction::Callees } else { Direction::Callers }, from),
                (None, Some(from)) => (CallRoots::Matching(from), Direction::Callees, None),
                (None, None) => return Err("callgraph needs a target: CLASS METHOD, --to RULE or --from RULE".into()),
            };
            let unless = unless.iter().map(|u| io.rule(u)).collect::<Result<Vec<_>, _>>()?;
            let engine = io.engine(common, &apk_path);
            let q = CallQuery { depth, max_nodes, virtual_calls, from, unless, ..CallQuery::new(roots, direction) };
            let tree = engine.call_graph_cancellable(&q, io.cancel).map_err(|e| e.to_string())?;
            io.emit_tree(output.as_ref(), &tree.lines(), &tree.footer())?;
            for e in &tree.errors {
                io.note(format_args!("Warning: {e}"));
            }
            if common.debug {
                io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
            }
            if !tree.errors.is_empty() {
                return Ok(EXIT_PARTIAL);
            }
        }
        Command::Hierarchy { output, supers, depth, max_nodes, method, apk_path, class } => {
            let class = names::format_class_name(&class).map_err(|e| e.to_string())?;
            let direction = if supers { Lineage::Supers } else { Lineage::Subclasses };
            let q = HierarchyQuery { class, direction, depth, max_nodes, method };
            let tree = io.engine(common, &apk_path).hierarchy_cancellable(&q, io.cancel).map_err(|e| e.to_string())?;
            let rows: Vec<String> = tree.lines().into_iter().chain(tree.definition_lines()).collect();
            io.emit_tree(output.as_ref(), &rows, &tree.footer())?;
            for e in &tree.errors {
                io.note(format_args!("Warning: {e}"));
            }
            if !tree.errors.is_empty() {
                return Ok(EXIT_PARTIAL);
            }
        }
        Command::Mcp { .. } | Command::Cache { .. } | Command::Daemon { .. } | Command::Config { .. } => {
            unreachable!("run handles the resident and maintenance commands")
        }
    }
    Ok(EXIT_OK)
}

fn run(cli: Cli, t_start: Instant) -> Result<u8, String> {
    let common = cli.common;
    match cli.command {
        Command::Mcp { max_entry_mb, max_ratio, sdk_prefixes, structured } => {
            let spill_bytes = common.config().cache_spill.value.0;
            let mut opts = asc_mcp::Options::new(common.config().fixed_threads(), common.debug, common.resident_cache());
            opts.limits.max_entry_bytes = max_entry_mb.saturating_mul(1 << 20);
            opts.limits.max_ratio = max_ratio;
            if let Some(p) = sdk_prefixes {
                opts.sdk_prefixes = p;
            }
            opts.structured = match structured {
                StructuredArg::Compact => asc_mcp::output::Structured::Compact,
                StructuredArg::Full => asc_mcp::output::Structured::Full,
            };
            if spill_bytes == 0 {
                opts.spill_dir = None;
            }
            opts.spill_bytes = spill_bytes;
            asc_mcp::serve(std::io::stdin().lock(), std::io::stdout(), opts).map_err(|e| format!("mcp: {e}"))?;
        }
        Command::Cache { action } => {
            let Some(cache) = common.disk_cache() else { return Err("no cache directory could be determined".into()) };
            match action {
                CacheAction::Path => println!("{}", cache.dir().display()),
                CacheAction::Stats => {
                    let (apks, files, bytes) = cache.stats();
                    println!("{}\n{apks} APKs, {files} files, {}", cache.dir().display(), mib(bytes));
                    for (tier, t) in asc_engine::asc_cache::Tier::ALL.into_iter().zip(cache.tier_stats()) {
                        println!("  {:12} {} APKs, {} files, {}", tier.label(), t.apks, t.files, mib(t.bytes));
                    }
                    let budget = cache.budget();
                    let source = match budget.capacity {
                        DiskCapacity::Auto(_) => "auto",
                        DiskCapacity::Fixed(_) => "explicit",
                    };
                    println!("budget: {} ({source}), used {}", mib(budget.cap_bytes), mib(budget.used));
                    match budget.space {
                        Some((free, total)) => println!("file system: {} free of {}", mib(free), mib(total)),
                        None => println!("file system: free space unknown"),
                    }
                }
                CacheAction::Clear => {
                    let bytes = cache.clear().map_err(|e| e.to_string())?;
                    println!("freed {}", mib(bytes));
                }
            }
        }
        Command::Daemon { action } => return daemon_command(&common, action),
        Command::Config { action, json } => return settings::print(common.config(), action.as_ref(), json),
        command => {
            // Not locked: engine threads log to stderr themselves (`--debug`).
            let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
            let cancel = AtomicBool::new(false);
            let mut io = Io::new(&mut out, &mut err, &LocalEngines, &cancel);
            return run_query(&mut io, &common, command, t_start);
        }
    }
    Ok(EXIT_OK)
}

#[cfg(unix)]
fn daemon_command(common: &Common, action: DaemonAction) -> Result<u8, String> {
    daemon::command(common, &action)
}

#[cfg(not(unix))]
fn daemon_command(_common: &Common, _action: DaemonAction) -> Result<u8, String> {
    Err("the daemon needs Unix sockets; commands run in their own process".into())
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn main() -> ExitCode {
    let t_start = Instant::now();
    let parsed = Cli::try_parse();
    // clap exits 2 on usage errors, which would collide with `EXIT_PARTIAL`;
    // usage errors are ordinary errors (1), help/version are not errors (0).
    let mut cli = match parsed {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::from(1) } else { ExitCode::SUCCESS };
        }
    };
    if let Err(e) = cli.common.resolve() {
        eprintln!("Error: {e}");
        return ExitCode::from(1);
    }
    #[cfg(unix)]
    if let Some(code) = daemon::forward(&cli) {
        return ExitCode::from(code);
    }
    match run(cli, t_start) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_names_sort_by_number_then_name() {
        let mut names = vec!["classes10.dex", "extra.dex", "classes2.dex", "classes.dex", "classes02.dex", "classesX.dex"];
        names.sort_by(|a, b| dex_rank(a).cmp(&dex_rank(b)));
        assert_eq!(names, ["classes.dex", "classes2.dex", "classes10.dex", "classes02.dex", "classesX.dex", "extra.dex"]);
    }

    #[test]
    fn dex_order_holds_entries_until_earlier_ones_are_complete() {
        let mut order = DexOrder { order: vec!["classes.dex".into(), "classes2.dex".into()], next: 0, parts: 2, pending: HashMap::new() };
        assert!(order.push("classes2.dex", 1, "2b").is_empty());
        assert!(order.push("classes.dex", 1, "1b").is_empty(), "classes.dex still misses a part");
        assert_eq!(order.push("classes.dex", 0, "1a"), ["1a", "1b"]);
        assert!(order.push("extra.dex", 0, "x").is_empty());
        // A part that never came (a cancelled run) is released at the end, in order.
        assert_eq!(order.finish(), ["2b", "x"]);
    }
}
