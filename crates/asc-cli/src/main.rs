//! `droidasc` command line entry.

#[cfg(unix)]
mod daemon;
mod output;

use asc_engine::asc_cache::{DiskCache, DiskCapacity};
use asc_engine::{names, CacheConfig, CallQuery, Direction, Engine, FindOptions, HierarchyQuery, Lineage, RefContext};
use asc_findrefs::Query;
use clap::{Args, Parser, Subcommand, ValueEnum};
use output::{Io, LocalEngines};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const EXAMPLES: &str = "common:
  Class names accept both com.poc.Main and Lcom/poc/Main;.
  Commands with -o/--output write to stdout when the option is omitted.
  --threads N controls parallel APK scanning; --debug enables timing output.

examples:
  droidasc app.apk --gui
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
  droidasc callgraph app.apk com.poc.Main onCreate --depth 3
  droidasc callgraph app.apk com.poc.Main 'run(I)V' --callees
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
/// Exit status when `findrefs` skipped at least one DEX entry.
const EXIT_PARTIAL: u8 = 2;

/// Subcommand names and aliases (`classes` / `manifest` as in rasc).
const SUBCOMMANDS: [&str; 16] = [
    "getclass",
    "disassemble",
    "listclass",
    "classes",
    "getmanifest",
    "manifest",
    "manifest-summary",
    "resources",
    "xml",
    "findrefs",
    "callgraph",
    "hierarchy",
    "gui",
    "mcp",
    "cache",
    "daemon",
];

fn default_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8)
}

#[derive(Parser)]
#[command(name = "droidasc", about = "ASC tooling entry.", after_help = EXAMPLES, version, disable_version_flag = true)]
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
    #[arg(long, global = true)]
    debug: bool,
    /// Worker thread count (default: number of logical CPUs).
    #[arg(long, alias = "thread", global = true, value_name = "N", default_value_t = default_threads())]
    threads: usize,
    /// Do not read or write the on-disk cache of inflated DEX files.
    #[arg(long, global = true)]
    no_cache: bool,
    /// Cache directory (default: $DROIDASC_CACHE_DIR, $XDG_CACHE_HOME/droidasc or ~/.cache/droidasc).
    #[arg(long, global = true, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
    /// On-disk cache budget, in MiB (default: $DROIDASC_CACHE_MAX_MB, else
    /// automatic: 20% of the cache's file system room, at most 4096, never
    /// below a 1 GiB / 5% free-space reserve).
    #[arg(long, global = true, value_name = "MIB")]
    cache_max_mb: Option<u64>,
    /// In-memory cache budget of `gui` and `mcp`, in MiB (default: a quarter
    /// of available memory, at most 2048). One-shot commands keep no memory cache.
    #[arg(long, global = true, value_name = "MIB")]
    memory_mb: Option<usize>,
}

impl Common {
    /// The engine every subcommand uses: shared flags, disk cache unless
    /// disabled, and log lines on stderr so stdout stays clean for redirection.
    fn engine(&self, apk_path: &Path) -> Engine {
        let mut engine = Engine::new(apk_path).with_debug(self.debug).with_threads(self.threads).with_logger(|m| eprintln!("{m}"));
        if !self.no_cache {
            engine = engine.with_cache(CacheConfig { disk: self.disk_cache(), ..CacheConfig::default() });
        }
        engine
    }

    fn disk_cache(&self) -> Option<DiskCache> {
        let cache = match &self.cache_dir {
            Some(d) => DiskCache::open(d),
            None => DiskCache::open_default()?,
        };
        Some(match self.cache_max_mb {
            Some(mb) => cache.with_capacity(mb.saturating_mul(1 << 20)),
            None => cache,
        })
    }

    /// Cache of the resident hosts (`gui`, `mcp`): the memory budget plus
    /// the disk cache unless disabled.
    fn resident_cache(&self) -> CacheConfig {
        CacheConfig {
            memory_bytes: self.memory_mb.map_or_else(asc_engine::auto_memory_bytes, |mb| mb.saturating_mul(1 << 20)),
            disk: if self.no_cache { None } else { self.disk_cache() },
            // Without an explicit budget, share one with the user's other resident hosts.
            memory_auto: self.memory_mb.is_none(),
        }
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
        /// Render one exact method signature, e.g. run(I)V (no fields).
        #[arg(long = "method", value_name = "SIGNATURE")]
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
        /// Render one exact method signature, e.g. run(I)V (no fields).
        #[arg(long = "method", value_name = "SIGNATURE")]
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
        /// At most this many rows for --search.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
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
        /// with N smali lines around them, and their pc / source line.
        #[arg(long, global = true, value_name = "N", conflicts_with = "context_method")]
        context: Option<usize>,
        /// After each result, show the whole referencing method.
        #[arg(long, global = true)]
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
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// Declaring class (com.poc.Main or Lcom/poc/Main;).
        class: String,
        /// Method name (every overload) or exact signature, e.g. run(I)V.
        method: String,
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
    /// Launch the graphical browser.
    Gui {
        /// Path to the input APK file.
        apk_path: PathBuf,
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
        /// Disk budget of the directory replies over their budget are
        /// written to (`out/` in the cache directory); 0 pages them instead.
        #[arg(long, default_value_t = 64)]
        spill_mb: u64,
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
            Command::Gui { .. } | Command::Mcp { .. } | Command::Cache { .. } | Command::Daemon { .. } => None,
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
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy type pattern.
        value: String,
    },
    /// Find classes that extend the target class.
    Extends {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Target class in dotted or Dalvik form, e.g. android.app.Activity or Lcom/poc/Base;.
        value: String,
    },
    /// Find classes that implement the target interface.
    Impl {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Target interface in dotted or Dalvik form, e.g. android.os.IInterface.
        value: String,
    },
    /// Find references to methods.
    Method {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy method name.
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
    /// method:[CLASS->]NAME, field:[CLASS->]NAME (CLASS exact, or `~CLASS`
    /// fuzzy; NAME a regex / substring, or `=NAME` exact). The last column
    /// lists what each condition matched, in order.
    All {
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
    /// impl:CLASS), or several joined with `&` for a compound rule.
    Rules {
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
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Fuzzy field name.
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
    let rules = specs
        .iter()
        .map(|spec| {
            let parts: Vec<&str> = spec.split('&').map(str::trim).collect();
            if parts.len() == 1 {
                return names::parse_condition(parts[0]);
            }
            let all = parts.iter().map(|p| names::parse_condition(p)).collect::<Result<Vec<_>, _>>()?;
            Ok(Query::All { all, none: Vec::new() })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let engine = io.engine(common, apk_path);
    let cancel = io.cancel;
    let mut sink = io.sink(output.as_ref(), true)?;
    for (i, spec) in specs.iter().enumerate() {
        sink.line(&format!("# r{} {spec}", i + 1));
    }
    let mut errors = Vec::new();
    let mut totals = vec![0usize; rules.len()];
    let opts = FindOptions { aggregate: true, context };
    engine
        .find_refs_rules(&rules, opts, cancel, &mut |i, batch| {
            if let Some(e) = batch.error {
                errors.push(format!("{}: {e}", batch.entry_name));
            }
            totals[i] += batch.results.len();
            for r in &batch.results {
                for (j, line) in r.text().lines().enumerate() {
                    sink.line(&if j == 0 { format!("r{} | {line}", i + 1) } else { format!("r{} |{line}", i + 1) });
                }
            }
            sink.flush_stdout();
        })
        .map_err(|e| e.to_string())?;
    for (i, n) in totals.iter().enumerate() {
        sink.line(&format!("# r{} {n} results", i + 1));
    }
    let io_result = sink.finish();
    errors.sort();
    errors.dedup();
    for e in &errors {
        io.note(format_args!("Warning: {e}"));
    }
    if common.debug {
        io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
    }
    io_result?;
    Ok(if errors.is_empty() { EXIT_OK } else { EXIT_PARTIAL })
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

fn getclass(io: &mut Io<'_>, common: &Common, args: ClassArgs, t_start: Instant) -> Result<(), String> {
    let descriptor = names::format_class_name(&args.dalvik_class).map_err(|e| e.to_string())?;
    let engine = io.engine(common, &args.apk_path);
    let opts = asc_engine::SmaliOptions { line_numbers: args.debug_info, param_names: args.debug_info };
    let mut src = engine.get_class_method(&descriptor, opts, args.method_signature.as_deref()).map_err(|e| e.to_string())?;
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
    io.emit(&src.source)
}

/// Write a tree command's text to `-o` or stdout.
fn emit_or_write(io: &mut Io<'_>, output: Option<&PathBuf>, text: &str) -> Result<(), String> {
    match output {
        Some(p) => io.write_file(p, text.as_bytes()),
        None => io.emit(text),
    }
}

/// Run a one-shot command (everything but `gui`, `mcp`, `cache` and
/// `daemon`, which [`run`] handles itself) against `io`: the exit status.
fn run_query(io: &mut Io<'_>, common: &Common, command: Command, t_start: Instant) -> Result<u8, String> {
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
                None => io.emit(&text)?,
            }
            if common.debug {
                io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
            }
        }
        Command::Getmanifest { output, resolve, apk_path } => {
            let engine = io.engine(common, &apk_path);
            let xml = if resolve { engine.manifest_xml_resolved() } else { engine.manifest_xml() }.map_err(|e| e.to_string())?;
            io.write_output(output.as_ref(), &xml)?;
            io.emit(&xml)?;
            if common.debug {
                io.note(format_args!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros()));
            }
        }
        Command::ManifestSummary { json, output, apk_path } => {
            let summary = io.engine(common, &apk_path).manifest_summary().map_err(|e| e.to_string())?;
            let text = if json { format!("{:#}", summary.json()) } else { summary.lines().join("\n") };
            io.write_output(output.as_ref(), &text)?;
            io.emit(&text)?;
        }
        Command::Resources { search, literal, field, resolve, limit, output, apk_path, query } => {
            let engine = io.engine(common, &apk_path);
            let mut note = None;
            let mut sink = io.sink(output.as_ref(), output.is_none())?;
            match (search, query) {
                (Some(pattern), _) => {
                    let field = match field.as_str() {
                        "name" => asc_engine::ResourceField::Name,
                        "value" => asc_engine::ResourceField::Value,
                        "any" => asc_engine::ResourceField::Any,
                        other => return Err(format!("--in must be name, value or any, not {other}")),
                    };
                    let (rows, total) = engine.search_resources(&pattern, literal, field, limit).map_err(|e| e.to_string())?;
                    rows.iter().for_each(|r| sink.line(&r.line()));
                    if total > rows.len() {
                        note = Some(format!("Note: {} of {total} matches shown; raise --limit for more", rows.len()));
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
            io.emit(&xml)?;
        }
        Command::Findrefs { apk_path, context, context_method, find } => {
            let context = match (context, context_method) {
                (_, true) => RefContext::Method,
                (Some(n), false) => RefContext::Lines(n),
                (None, false) => RefContext::None,
            };
            if let Find::Rules { output, file, rules } = find {
                return findrefs_rules(io, common, &apk_path, context, output, file, rules, t_start);
            }
            let (query, output) = match find {
                Find::Rules { .. } => unreachable!("handled above"),
                Find::All { output, none, conditions } => {
                    let parse = |c: &[String]| c.iter().map(|c| names::parse_condition(c)).collect::<Result<Vec<_>, _>>();
                    let all = parse(&conditions).map_err(|e| e.to_string())?;
                    (Query::All { all, none: parse(&none).map_err(|e| e.to_string())? }, output)
                }
                Find::String { output, literal: false, value } => (Query::String(value), output),
                Find::String { output, literal: true, value } => (Query::StringLiteral(value), output),
                Find::Type { output, value } => (Query::Type(value), output),
                // The class-def lookups need the precise Dalvik form.
                Find::Extends { output, value } => (Query::Extends(names::format_class_name(&value).map_err(|e| e.to_string())?), output),
                Find::Impl { output, value } => (Query::Implements(names::format_class_name(&value).map_err(|e| e.to_string())?), output),
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
            let mut sink = io.sink(output.as_ref(), true)?;
            let mut errors = Vec::new();
            let opts = FindOptions { aggregate: true, context };
            engine
                .find_refs_opts(&query, opts, cancel, &mut |batch| {
                    if let Some(e) = batch.error {
                        errors.push(format!("{}: {e}", batch.entry_name));
                    }
                    for r in &batch.results {
                        sink.line(&r.text());
                    }
                    sink.flush_stdout();
                })
                .map_err(|e| e.to_string())?;
            let io_result = sink.finish();
            for e in &errors {
                io.note(format_args!("Warning: {e}"));
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
        Command::Callgraph { output, callees, depth, max_nodes, virtual_calls, apk_path, class, method } => {
            let class = names::format_class_name(&class).map_err(|e| e.to_string())?;
            let direction = if callees { Direction::Callees } else { Direction::Callers };
            let engine = io.engine(common, &apk_path);
            let q = CallQuery { class, method, direction, depth, max_nodes, virtual_calls };
            let tree = engine.call_graph(&q).map_err(|e| e.to_string())?;
            let mut text = tree.lines().join("\n");
            text.push('\n');
            text.push_str(&tree.footer());
            text.push('\n');
            emit_or_write(io, output.as_ref(), &text)?;
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
            let tree = io
                .engine(common, &apk_path)
                .hierarchy(&HierarchyQuery { class, direction, depth, max_nodes, method })
                .map_err(|e| e.to_string())?;
            let mut text: String = tree.lines().into_iter().chain(tree.definition_lines()).map(|l| l + "\n").collect();
            text.push_str(&tree.footer());
            text.push('\n');
            emit_or_write(io, output.as_ref(), &text)?;
            for e in &tree.errors {
                io.note(format_args!("Warning: {e}"));
            }
            if !tree.errors.is_empty() {
                return Ok(EXIT_PARTIAL);
            }
        }
        Command::Gui { .. } | Command::Mcp { .. } | Command::Cache { .. } | Command::Daemon { .. } => {
            unreachable!("run handles the resident and maintenance commands")
        }
    }
    Ok(EXIT_OK)
}

fn run(cli: Cli, t_start: Instant) -> Result<u8, String> {
    let common = cli.common;
    match cli.command {
        Command::Gui { apk_path } => {
            launch_gui(apk_path, common.threads, common.debug, common.resident_cache())?;
        }
        Command::Mcp { max_entry_mb, max_ratio, sdk_prefixes, structured, spill_mb } => {
            let mut opts = asc_mcp::Options::new(common.threads, common.debug, common.resident_cache());
            opts.limits.max_entry_bytes = max_entry_mb.saturating_mul(1 << 20);
            opts.limits.max_ratio = max_ratio;
            if let Some(p) = sdk_prefixes {
                opts.sdk_prefixes = p;
            }
            opts.structured = match structured {
                StructuredArg::Compact => asc_mcp::output::Structured::Compact,
                StructuredArg::Full => asc_mcp::output::Structured::Full,
            };
            if spill_mb == 0 {
                opts.spill_dir = None;
            }
            opts.spill_bytes = spill_mb.saturating_mul(1 << 20);
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
                        DiskCapacity::Auto => "auto",
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

#[cfg(feature = "gui")]
fn launch_gui(apk_path: PathBuf, threads: usize, debug: bool, cache: CacheConfig) -> Result<(), String> {
    asc_gui::launch(apk_path, threads, debug, cache).map_err(|e| e.to_string())
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(not(feature = "gui"))]
fn launch_gui(_apk_path: PathBuf, _threads: usize, _debug: bool, _cache: CacheConfig) -> Result<(), String> {
    Err("this build was compiled without the `gui` feature".into())
}

/// Accept the legacy `droidasc app.apk --gui [--threads N] [--debug]` form.
///
/// Only rewrites when `--gui` is present and no subcommand name is, so a
/// normal invocation is never touched even if it mentions `--gui` somewhere.
fn legacy_gui_args(args: &[String]) -> Option<Vec<String>> {
    let (program, rest) = args.split_first()?;
    if !rest.iter().any(|a| a == "--gui") || rest.iter().any(|a| SUBCOMMANDS.contains(&a.as_str())) {
        return None;
    }
    let mut out = vec![program.clone(), "gui".to_string()];
    out.extend(rest.iter().filter(|a| *a != "--gui" && *a != "--gui-foreground").cloned());
    Some(out)
}

fn main() -> ExitCode {
    let t_start = Instant::now();
    let args: Vec<String> = std::env::args().collect();
    let parsed = match legacy_gui_args(&args) {
        Some(rewritten) => Cli::try_parse_from(rewritten),
        None => Cli::try_parse(),
    };
    // clap exits 2 on usage errors, which would collide with `EXIT_PARTIAL`;
    // usage errors are ordinary errors (1), help/version are not errors (0).
    let cli = match parsed {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { ExitCode::from(1) } else { ExitCode::SUCCESS };
        }
    };
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

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn legacy_gui_form_is_rewritten() {
        let out = legacy_gui_args(&argv("droidasc app.apk --gui --threads 4 --debug")).unwrap();
        assert_eq!(out, argv("droidasc gui app.apk --threads 4 --debug"));
        let out = legacy_gui_args(&argv("droidasc --gui-foreground --gui app.apk")).unwrap();
        assert_eq!(out, argv("droidasc gui app.apk"));
    }

    #[test]
    fn legacy_rewrite_leaves_subcommands_and_empty_argv_alone() {
        assert!(legacy_gui_args(&[]).is_none());
        assert!(legacy_gui_args(&argv("droidasc")).is_none());
        assert!(legacy_gui_args(&argv("droidasc findrefs app.apk string --gui")).is_none());
        assert!(legacy_gui_args(&argv("droidasc gui app.apk --gui")).is_none());
        assert!(legacy_gui_args(&argv("droidasc getclass app.apk com.poc.Main")).is_none());
    }
}
