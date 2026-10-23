//! Where a command's output goes: the process's own stdout / stderr, or a
//! daemon connection that relays them to the client ([`crate::daemon`]).
//! Commands write through [`Io`] only, so both run the same code.

use crate::Common;
use asc_engine::Engine;
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

/// The output streams, working directory and engines of one command.
pub(crate) struct Io<'a> {
    pub(crate) out: &'a mut dyn Write,
    pub(crate) err: &'a mut dyn Write,
    /// Relative paths resolve against this; `None`: the process's own.
    cwd: Option<&'a Path>,
    engines: &'a dyn Engines,
    pub(crate) cancel: &'a AtomicBool,
}

impl<'a> Io<'a> {
    pub(crate) fn new(out: &'a mut dyn Write, err: &'a mut dyn Write, engines: &'a dyn Engines, cancel: &'a AtomicBool) -> Io<'a> {
        Io { out, err, cwd: None, engines, cancel }
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

    pub(crate) fn engine(&self, common: &Common, apk_path: &Path) -> Arc<Engine> {
        self.engines.engine(common, &self.path(apk_path))
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

    /// A line sink on stdout (unless `to_stdout` is false) plus the `-o` file.
    pub(crate) fn sink(&mut self, output: Option<&PathBuf>, to_stdout: bool) -> Result<LineSink<BufWriter<&mut (dyn Write + 'a)>>, String> {
        let file = match output {
            Some(p) => Some((p.clone(), BufWriter::new(self.create_file(p)?))),
            None => None,
        };
        let stdout = to_stdout.then(|| BufWriter::new(&mut *self.out));
        Ok(LineSink { stdout, file, error: None })
    }
}

/// Line sink for `findrefs`: stdout plus an optional `-o` file.
///
/// A closed stdout (`| head`) silently stops the stdout copy while the file
/// keeps being written. Any other I/O error is remembered (first one wins),
/// the failing destination is dropped, and the error is reported at the end.
pub(crate) struct LineSink<W: Write> {
    stdout: Option<W>,
    file: Option<(PathBuf, BufWriter<File>)>,
    error: Option<String>,
}

impl<W: Write> LineSink<W> {
    #[cfg(test)]
    fn new(stdout: W, output: Option<&PathBuf>) -> Result<LineSink<W>, String> {
        let file = match output {
            Some(p) => Some((p.clone(), BufWriter::new(File::create(p).map_err(|e| e.to_string())?))),
            None => None,
        };
        Ok(LineSink { stdout: Some(stdout), file, error: None })
    }

    fn fail(&mut self, msg: String) {
        if self.error.is_none() {
            self.error = Some(msg);
        }
    }

    pub(crate) fn line(&mut self, line: &str) {
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

    pub(crate) fn finish(mut self) -> Result<(), String> {
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
    fn relative_paths_resolve_against_the_client_directory() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let cancel = AtomicBool::new(false);
        let cwd = Path::new("/work/dir");
        let io = Io::new(&mut out, &mut err, &LocalEngines, &cancel).with_cwd(cwd);
        assert_eq!(io.path(Path::new("a.apk")), Path::new("/work/dir/a.apk"));
        assert_eq!(io.path(Path::new("/abs/a.apk")), Path::new("/abs/a.apk"));
    }
}
