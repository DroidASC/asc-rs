//! Where a command's output goes: the process's own stdout / stderr, or a
//! daemon connection that relays them to the client ([`crate::daemon`]).
//! Commands write through [`Io`] only, so both run the same code.

use crate::Common;
use asc_engine::{condition, Engine};
use asc_findrefs::Query;
use asc_mcp::output::SpillDir;
use std::borrow::Cow;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Supplies the engine a command runs on.
pub(crate) trait Engines: Sync {
    fn engine(&self, common: &Common, apk_path: &Path) -> Arc<Engine>;
}

/// A fresh engine per command, as a one-shot process uses.
pub(crate) struct LocalEngines;

impl Engines for LocalEngines {
    fn engine(&self, common: &Common, apk_path: &Path) -> Arc<Engine> {
        Arc::new(common.engine(apk_path))
    }
}

/// Which records of a command's output reach stdout (`--offset`,
/// `--limit`, `--max-bytes`). The whole output then goes to a file the last
/// stdout line names, so an agent sees a bounded reply and can grep the rest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Window {
    /// Records skipped before the first one shown.
    pub(crate) offset: usize,
    /// At most this many records shown.
    pub(crate) limit: Option<usize>,
    /// At most this many bytes of records shown (whole records only).
    pub(crate) max_bytes: Option<usize>,
}

impl Window {
    /// No option given: everything goes to stdout, exactly as without a window.
    pub(crate) fn is_everything(&self) -> bool {
        *self == Window::default()
    }
}

/// Where the whole output goes when the window cuts it: a spill directory
/// (`out/` in the cache directory) under a byte budget. `None` (`--spill-mb 0`):
/// nowhere, the hint gives the `--offset` of the next records instead.
#[derive(Clone, Debug)]
pub(crate) struct SpillTarget {
    pub(crate) dir: PathBuf,
    pub(crate) bytes: u64,
}

/// The output streams, working directory and engines of one command.
pub(crate) struct Io<'a> {
    pub(crate) out: &'a mut dyn Write,
    pub(crate) err: &'a mut dyn Write,
    /// Relative paths resolve against this; `None`: the process's own.
    cwd: Option<&'a Path>,
    engines: &'a dyn Engines,
    pub(crate) cancel: &'a AtomicBool,
    pub(crate) window: Window,
    pub(crate) spill: Option<SpillTarget>,
}

impl<'a> Io<'a> {
    pub(crate) fn new(out: &'a mut dyn Write, err: &'a mut dyn Write, engines: &'a dyn Engines, cancel: &'a AtomicBool) -> Io<'a> {
        Io { out, err, cwd: None, engines, cancel, window: Window::default(), spill: None }
    }

    /// Resolve relative paths against `cwd` (a client's directory).
    pub(crate) fn with_cwd(mut self, cwd: &'a Path) -> Io<'a> {
        self.cwd = Some(cwd);
        self
    }

    /// `path` as this command's process would open it. Messages keep showing
    /// the path as given.
    pub(crate) fn path<'p>(&self, path: &'p Path) -> Cow<'p, Path> {
        match self.cwd {
            Some(cwd) if path.is_relative() => Cow::Owned(cwd.join(path)),
            _ => Cow::Borrowed(path),
        }
    }

    /// A findrefs rule, its `method:@FILE` sets read as [`Io::path`] opens files.
    pub(crate) fn rule(&self, spec: &str) -> Result<Query, String> {
        condition::parse_rule_in(spec, self.cwd).map_err(|e| e.to_string())
    }

    /// One findrefs condition, read as [`Io::rule`] does.
    pub(crate) fn condition(&self, spec: &str) -> Result<Query, String> {
        condition::parse_condition_in(spec, self.cwd).map_err(|e| e.to_string())
    }

    pub(crate) fn engine(&self, common: &Common, apk_path: &Path) -> Arc<Engine> {
        match self.cwd {
            Some(cwd) => self.engines.engine(common, &Engine::resolve_path(apk_path, cwd)),
            None => self.engines.engine(common, apk_path),
        }
    }

    /// One line on stderr. A failing stderr is ignored: there is nowhere left
    /// to report it.
    pub(crate) fn note(&mut self, line: impl Display) {
        let _ = writeln!(self.err, "{line}");
    }

    /// Print to stdout, treating a closed pipe (e.g. `| head`) as a clean exit.
    pub(crate) fn emit(&mut self, text: &str) -> Result<(), String> {
        let out = &mut *self.out;
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

    pub(crate) fn create_file(&self, path: &Path) -> Result<File, String> {
        File::create(self.path(path)).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// Write `bytes` to `path` (`-o`, `--dump-dex`).
    pub(crate) fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        std::fs::write(self.path(path), bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    /// `-o` copy of a text output, newline-terminated.
    pub(crate) fn write_output(&self, path: Option<&PathBuf>, text: &str) -> Result<(), String> {
        if let Some(p) = path {
            let mut f = self.create_file(p)?;
            f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            if !text.ends_with('\n') {
                f.write_all(b"\n").map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// Print a whole text as records, one per line, through the window
    /// (`saved`: the `-o` file already holding all of it).
    pub(crate) fn emit_records(&mut self, text: &str, saved: Option<&PathBuf>) -> Result<(), String> {
        if self.window.is_everything() {
            return self.emit(text);
        }
        let mut sink = self.sink(None, true)?;
        sink.saved = saved.cloned();
        text.lines().for_each(|l| sink.line(l));
        sink.finish()
    }

    /// A tree (callgraph, hierarchy): its rows as records, the footer always
    /// shown; to `-o` instead of stdout when given.
    pub(crate) fn emit_tree(&mut self, output: Option<&PathBuf>, rows: &[String], footer: &str) -> Result<(), String> {
        if output.is_some() || self.window.is_everything() {
            let mut text: String = rows.iter().map(|l| format!("{l}\n")).collect();
            text.push_str(footer);
            text.push('\n');
            return match output {
                Some(p) => self.write_file(p, text.as_bytes()),
                None => self.emit(&text),
            };
        }
        let mut sink = self.sink(None, true)?;
        rows.iter().for_each(|l| sink.line(l));
        sink.comment(footer);
        sink.finish()
    }

    /// A line sink on stdout (unless `to_stdout` is false) plus the `-o`
    /// file. The window applies to stdout; the `-o` file gets everything.
    pub(crate) fn sink(&mut self, output: Option<&PathBuf>, to_stdout: bool) -> Result<LineSink<BufWriter<&mut (dyn Write + 'a)>>, String> {
        let file = match output {
            Some(p) => Some((p.clone(), BufWriter::new(self.create_file(p)?))),
            None => None,
        };
        let window = if to_stdout { self.window } else { Window::default() };
        let stdout = to_stdout.then(|| BufWriter::new(&mut *self.out));
        let full = (!window.is_everything() && file.is_none()).then(String::new);
        Ok(LineSink {
            stdout,
            file,
            error: None,
            window,
            spill: self.spill.clone(),
            saved: output.cloned(),
            full,
            records: 0,
            shown: 0,
            shown_bytes: 0,
            cut: false,
        })
    }
}

/// Record sink: stdout through a [`Window`], plus an optional `-o` file.
///
/// A record is one [`LineSink::line`] call (a findrefs result with its
/// context lines is one record); [`LineSink::comment`] lines (`# ...`
/// headers and totals) are always shown and never counted. Once the window
/// cuts stdout, the whole output is kept for the file the hint names.
///
/// A closed stdout (`| head`) silently stops the stdout copy while the file
/// keeps being written. Any other I/O error is remembered (first one wins),
/// the failing destination is dropped, and the error is reported at the end.
pub(crate) struct LineSink<W: Write> {
    stdout: Option<W>,
    file: Option<(PathBuf, BufWriter<File>)>,
    error: Option<String>,
    window: Window,
    spill: Option<SpillTarget>,
    /// Where the whole output already is (`-o`), named by the hint.
    saved: Option<PathBuf>,
    /// The whole output, kept while a window applies and no `-o` file holds it.
    full: Option<String>,
    records: usize,
    shown: usize,
    shown_bytes: usize,
    /// The window stopped stdout before the last record.
    cut: bool,
}

impl<W: Write> LineSink<W> {
    #[cfg(test)]
    fn new(stdout: W, output: Option<&PathBuf>) -> Result<LineSink<W>, String> {
        LineSink::windowed(stdout, output, Window::default(), None)
    }

    #[cfg(test)]
    fn windowed(stdout: W, output: Option<&PathBuf>, window: Window, spill: Option<SpillTarget>) -> Result<LineSink<W>, String> {
        let file = match output {
            Some(p) => Some((p.clone(), BufWriter::new(File::create(p).map_err(|e| e.to_string())?))),
            None => None,
        };
        let full = (!window.is_everything() && file.is_none()).then(String::new);
        Ok(LineSink {
            stdout: Some(stdout),
            file,
            error: None,
            window,
            spill,
            saved: output.cloned(),
            full,
            records: 0,
            shown: 0,
            shown_bytes: 0,
            cut: false,
        })
    }

    fn fail(&mut self, msg: String) {
        if self.error.is_none() {
            self.error = Some(msg);
        }
    }

    /// One record.
    pub(crate) fn line(&mut self, line: &str) {
        self.records += 1;
        let show = self.records > self.window.offset && !self.cut && {
            let fits_count = self.window.limit.is_none_or(|n| self.shown < n);
            let fits_bytes = self.window.max_bytes.is_none_or(|n| self.shown_bytes + line.len() < n);
            fits_count && fits_bytes
        };
        if self.records > self.window.offset && !show {
            self.cut = true;
        }
        if show {
            self.shown += 1;
            self.shown_bytes += line.len() + 1;
        }
        self.write(line, show);
    }

    /// A `# ...` line that is always shown and is not a record.
    pub(crate) fn comment(&mut self, line: &str) {
        self.write(line, true);
    }

    fn write(&mut self, line: &str, to_stdout: bool) {
        if let Some(full) = self.full.as_mut() {
            full.push_str(line);
            full.push('\n');
        }
        if let Some(out) = self.stdout.as_mut().filter(|_| to_stdout) {
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
    pub(crate) fn flush_stdout(&mut self) {
        if let Some(out) = self.stdout.as_mut() {
            if let Err(e) = out.flush() {
                self.stdout = None;
                if e.kind() != ErrorKind::BrokenPipe {
                    self.fail(format!("cannot write to stdout: {e}"));
                }
            }
        }
    }

    /// The last stdout line when the window cut the output: what was shown,
    /// where the whole output is and the `--offset` of the next records.
    fn hint(&mut self) -> Option<String> {
        if !self.cut {
            let past_end = self.shown == 0 && self.window.offset > 0 && self.records > 0;
            return past_end.then(|| format!("# no records after --offset {} ({} in all)", self.window.offset, self.records));
        }
        let (first, last, total) = (self.window.offset + 1, self.window.offset + self.shown, self.records);
        let shown = if self.shown == 0 { format!("no records of {total}") } else { format!("records {first}-{last} of {total}") };
        let next = self.window.offset + self.shown;
        let more = if last < total { format!(", or rerun with --offset {next}") } else { String::new() };
        let place = match (&self.saved, self.full.take(), &self.spill) {
            (Some(p), _, _) => Ok(p.display().to_string()),
            (None, Some(full), Some(spill)) => SpillDir::new(spill.dir.clone(), spill.bytes)
                .write(&full)
                .map(|p| p.display().to_string())
                .map_err(|e| format!("cannot write the full output to {}: {e}", spill.dir.display())),
            (None, _, _) => Err(String::new()),
        };
        Some(match place {
            Ok(path) => format!("# {shown} shown; full output in {path} (grep it{more})"),
            Err(why) if why.is_empty() => format!("# {shown} shown{}", more.replacen(", or", ";", 1)),
            Err(why) => format!("# {shown} shown{}; {why}", more.replacen(", or", ";", 1)),
        })
    }

    pub(crate) fn finish(mut self) -> Result<(), String> {
        if let Some(hint) = self.hint() {
            if let Some(out) = self.stdout.as_mut() {
                if let Err(e) = writeln!(out, "{hint}") {
                    self.stdout = None;
                    if e.kind() != ErrorKind::BrokenPipe {
                        self.fail(format!("cannot write to stdout: {e}"));
                    }
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let mut sink = LineSink::new(Closed, Some(&path)).unwrap();
        sink.line("a");
        sink.flush_stdout();
        sink.line("b");
        assert!(sink.stdout.is_none());
        sink.finish().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
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

    #[test]
    fn window_shows_whole_records_and_always_the_comments() {
        let dir = tempfile::tempdir().unwrap();
        let spill = SpillTarget { dir: dir.path().join("out"), bytes: 1 << 20 };
        let mut out = Vec::new();
        let window = Window { offset: 1, limit: Some(2), max_bytes: None };
        let mut sink = LineSink::windowed(&mut out, None, window, Some(spill)).unwrap();
        sink.comment("# head");
        for r in ["a", "b\n  b2", "c", "d"] {
            sink.line(r);
        }
        sink.comment("# 4 results");
        sink.finish().unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[..5], ["# head", "b", "  b2", "c", "# 4 results"]);
        assert!(lines[5].starts_with("# records 2-3 of 4 shown; full output in "), "{text}");
        assert!(lines[5].ends_with("(grep it, or rerun with --offset 3)"), "{text}");
        let file = lines[5].split("full output in ").nth(1).unwrap().split(" (").next().unwrap();
        assert_eq!(std::fs::read_to_string(file).unwrap(), "# head\na\nb\n  b2\nc\nd\n# 4 results\n");
    }

    #[test]
    fn a_record_over_the_byte_budget_stops_the_output() {
        let mut out = Vec::new();
        let window = Window { offset: 0, limit: None, max_bytes: Some(4) };
        let mut sink = LineSink::windowed(&mut out, None, window, None).unwrap();
        for r in ["ab", "cdef", "g"] {
            sink.line(r);
        }
        sink.finish().unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "ab\n# records 1-1 of 3 shown; rerun with --offset 1\n");
    }

    #[test]
    fn relative_paths_resolve_against_the_client_directory() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let cancel = AtomicBool::new(false);
        let cwd = Path::new("/work/dir");
        let io = Io::new(&mut out, &mut err, &LocalEngines, &cancel).with_cwd(cwd);
        assert_eq!(io.path(Path::new("a.apk")), Path::new("/work/dir/a.apk"));
        assert_eq!(io.path(Path::new("/abs/a.apk")), Path::new("/abs/a.apk"));
    }
}
