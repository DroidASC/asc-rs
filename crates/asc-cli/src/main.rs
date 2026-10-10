//! `droidasc` command line entry.

use asc_engine::asc_cache::DiskCache;
use asc_engine::{names, CacheConfig, Engine};
use asc_findrefs::Query;
use clap::{Args, Parser, Subcommand};
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

const EXAMPLES: &str = "examples:
  droidasc app.apk --gui
  droidasc getclass app.apk 'Lcom/poc/Main;' -o Main.smali
  droidasc getclass app.apk com.poc.Main --threads 16
  droidasc getclass app.apk com.poc.Main --dump-dex Main.dex
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk method run --class com.poc.Main --exact
  droidasc findrefs app.apk field apiKey -o field_refs.txt
  droidasc findrefs app.apk string token --no-cache
  droidasc cache stats

exit status:
  0  success
  1  error (bad arguments, unreadable APK, class not found, output not writable, ...)
  2  findrefs finished, but one or more DEX entries could not be searched (details on stderr)

Debug output (--debug) goes to stderr so stdout can be redirected.";

/// Exit status when `findrefs` skipped at least one DEX entry.
const EXIT_PARTIAL: u8 = 2;

const SUBCOMMANDS: [&str; 5] = ["getclass", "getmanifest", "findrefs", "gui", "cache"];

fn default_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8)
}

#[derive(Parser)]
#[command(name = "droidasc", about = "ASC tooling entry.", after_help = EXAMPLES, version)]
struct Cli {
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
}

impl Common {
    /// The engine every subcommand uses: shared flags, disk cache unless
    /// disabled, and log lines on stderr so stdout stays clean for redirection.
    fn engine(&self, apk_path: &Path) -> Engine {
        let mut engine = Engine::new(apk_path).with_debug(self.debug).with_threads(self.threads).with_logger(|m| eprintln!("{m}"));
        if !self.no_cache {
            engine = engine.with_cache(CacheConfig { memory_bytes: 0, disk: self.disk_cache() });
        }
        engine
    }

    fn disk_cache(&self) -> Option<DiskCache> {
        match &self.cache_dir {
            Some(d) => Some(DiskCache::open(d)),
            None => DiskCache::open_default(),
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
        /// Path to the input APK file.
        apk_path: PathBuf,
        /// The Dalvik format class name to extract (e.g., Lcom/poc/Main; or com.poc.Main).
        dalvik_class: String,
    },
    /// Decode AndroidManifest.xml from APK and print it as XML.
    Getmanifest {
        /// Also write the decoded manifest to this file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Path to the input APK file.
        apk_path: PathBuf,
    },
    /// Find code references for string/type/method/field across all DEX entries in APK.
    ///
    /// Exits with status 2 when some DEX entries could not be searched; the
    /// results of the other entries are still printed.
    Findrefs {
        /// Path to the input APK file.
        apk_path: PathBuf,
        #[command(subcommand)]
        find: Find,
    },
    /// Launch the graphical browser.
    Gui {
        /// Path to the input APK file.
        apk_path: PathBuf,
    },
    /// Inspect or clear the on-disk cache of inflated DEX files.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
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

fn create_file(path: &Path) -> Result<File, String> {
    File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn write_output(path: Option<&PathBuf>, text: &str) -> Result<(), String> {
    if let Some(p) = path {
        let mut f = create_file(p)?;
        f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        if !text.ends_with('\n') {
            f.write_all(b"\n").map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Print to stdout, treating a closed pipe (e.g. `| head`) as a clean exit.
fn emit(text: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let res = out
        .write_all(text.as_bytes())
        .and_then(|_| if text.ends_with('\n') { Ok(()) } else { out.write_all(b"\n") })
        .and_then(|_| out.flush());
    match res {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(format!("cannot write to stdout: {e}")),
    }
}

/// Line sink for `findrefs`: stdout plus an optional `-o` file.
///
/// A closed stdout (`| head`) silently stops the stdout copy while the file
/// keeps being written. Any other I/O error is remembered (first one wins),
/// the failing destination is dropped, and the error is reported at the end.
struct LineSink<W: Write> {
    stdout: Option<W>,
    file: Option<(PathBuf, BufWriter<File>)>,
    error: Option<String>,
}

impl<W: Write> LineSink<W> {
    fn new(stdout: W, output: Option<&PathBuf>) -> Result<LineSink<W>, String> {
        let file = match output {
            Some(p) => Some((p.clone(), BufWriter::new(create_file(p)?))),
            None => None,
        };
        Ok(LineSink { stdout: Some(stdout), file, error: None })
    }

    fn fail(&mut self, msg: String) {
        if self.error.is_none() {
            self.error = Some(msg);
        }
    }

    fn line(&mut self, line: &str) {
        if let Some(out) = self.stdout.as_mut() {
            if let Err(e) = writeln!(out, "{line}") {
                self.stdout = None;
                if e.kind() != ErrorKind::BrokenPipe {
                    self.fail(format!("cannot write to stdout: {e}"));
                }
            }
        }
        if let Some((path, f)) = self.file.as_mut() {
            if let Err(e) = writeln!(f, "{line}") {
                let msg = format!("cannot write {}: {e}", path.display());
                self.file = None;
                self.fail(msg);
            }
        }
    }

    /// Flush stdout after a batch so results stream while the search runs.
    fn flush_stdout(&mut self) {
        if let Some(out) = self.stdout.as_mut() {
            if let Err(e) = out.flush() {
                self.stdout = None;
                if e.kind() != ErrorKind::BrokenPipe {
                    self.fail(format!("cannot write to stdout: {e}"));
                }
            }
        }
    }

    fn finish(mut self) -> Result<(), String> {
        self.flush_stdout();
        if let Some((path, mut f)) = self.file.take() {
            if let Err(e) = f.flush() {
                self.fail(format!("cannot write {}: {e}", path.display()));
            }
        }
        match self.error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn run(cli: Cli, t_start: Instant) -> Result<ExitCode, String> {
    let common = cli.common.clone();
    match cli.command {
        Command::Getclass { output, no_debug_info, dump_dex, apk_path, dalvik_class } => {
            let descriptor = names::format_class_name(&dalvik_class).map_err(|e| e.to_string())?;
            let engine = common.engine(&apk_path);
            let opts = asc_engine::SmaliOptions { line_numbers: !no_debug_info, param_names: !no_debug_info };
            let src = engine.get_class_with(&descriptor, opts).map_err(|e| e.to_string())?;
            if let Some(w) = &src.warning {
                eprintln!("Warning: {w}");
            }
            if let Some(p) = &dump_dex {
                let rebuilt = src.rebuilt.as_ref().ok_or_else(|| format!("cannot write {}: the class was not rebuilt", p.display()))?;
                std::fs::write(p, &rebuilt.bytes).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
            }
            if common.debug {
                eprintln!("[DEBUG] Hit DEX: {}", src.dex_name);
                eprintln!("[DEBUG] APK Scan Time: {} us", src.scan_us);
                if let Some(r) = &src.rebuilt {
                    eprintln!(
                        "[DEBUG] Rebuilt DEX: {} bytes, {} strings, {} types, {} protos, {} fields, {} methods ({} with code)",
                        r.stats.size,
                        r.stats.strings,
                        r.stats.types,
                        r.stats.protos,
                        r.stats.fields,
                        r.stats.methods,
                        r.stats.methods_with_code
                    );
                }
                eprintln!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros());
                eprintln!("{}", "-".repeat(50));
            }
            write_output(output.as_ref(), &src.source)?;
            emit(&src.source)?;
        }
        Command::Getmanifest { output, apk_path } => {
            let engine = common.engine(&apk_path);
            let xml = engine.manifest_xml().map_err(|e| e.to_string())?;
            write_output(output.as_ref(), &xml)?;
            emit(&xml)?;
            if common.debug {
                eprintln!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros());
            }
        }
        Command::Findrefs { apk_path, find } => {
            let (query, output) = match find {
                Find::String { output, value } => (Query::String(value), output),
                Find::Type { output, value } => (Query::Type(value), output),
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
            let engine = common.engine(&apk_path);
            let stdout = std::io::stdout();
            let mut sink = LineSink::new(BufWriter::new(stdout.lock()), output.as_ref())?;
            let mut errors = Vec::new();
            engine
                .find_refs(&query, |batch| {
                    if let Some(e) = batch.error {
                        errors.push(format!("{}: {e}", batch.entry_name));
                    }
                    for r in &batch.results {
                        sink.line(&r.line());
                    }
                    sink.flush_stdout();
                })
                .map_err(|e| e.to_string())?;
            let io_result = sink.finish();
            for e in &errors {
                eprintln!("Warning: {e}");
            }
            if common.debug {
                let st = engine.cache_stats();
                eprintln!("[DEBUG] Cache: {} inflated, {} disk hits", st.inflates, st.disk_hits);
                eprintln!("[DEBUG] Total Execution Time: {} us", t_start.elapsed().as_micros());
            }
            io_result?;
            if !errors.is_empty() {
                eprintln!("Warning: {} DEX entr{} could not be searched", errors.len(), if errors.len() == 1 { "y" } else { "ies" });
                return Ok(ExitCode::from(EXIT_PARTIAL));
            }
        }
        Command::Gui { apk_path } => {
            launch_gui(apk_path, common.threads, common.debug, !common.no_cache)?;
        }
        Command::Cache { action } => {
            let Some(cache) = common.disk_cache() else { return Err("no cache directory could be determined".into()) };
            match action {
                CacheAction::Path => println!("{}", cache.dir().display()),
                CacheAction::Stats => {
                    let (apks, files, bytes) = cache.stats();
                    println!("{}\n{apks} APKs, {files} files, {:.1} MiB", cache.dir().display(), bytes as f64 / (1024.0 * 1024.0));
                }
                CacheAction::Clear => {
                    let bytes = cache.clear().map_err(|e| e.to_string())?;
                    println!("freed {:.1} MiB", bytes as f64 / (1024.0 * 1024.0));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "gui")]
fn launch_gui(apk_path: PathBuf, threads: usize, debug: bool, cache: bool) -> Result<(), String> {
    asc_gui::launch(apk_path, threads, debug, cache).map_err(|e| e.to_string())
}

#[cfg(not(feature = "gui"))]
fn launch_gui(_apk_path: PathBuf, _threads: usize, _debug: bool, _cache: bool) -> Result<(), String> {
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
    match run(cli, t_start) {
        Ok(code) => code,
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

    #[test]
    fn line_sink_keeps_writing_the_file_after_stdout_closes() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let dir = std::env::temp_dir().join(format!("droidasc-sink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.txt");
        let mut sink = LineSink::new(Closed, Some(&path)).unwrap();
        sink.line("a");
        sink.flush_stdout();
        sink.line("b");
        assert!(sink.stdout.is_none());
        sink.finish().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn line_sink_reports_other_stdout_errors() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = LineSink::new(Broken, None).unwrap();
        sink.line("a");
        sink.line("b");
        let err = sink.finish().unwrap_err();
        assert!(err.contains("stdout") && err.contains("disk full"), "{err}");
    }
}
