//! What a decompile request answers, and the header that says how it came about.

use asc_decompile::protocol::methods::{Language, MethodReport, MethodStatus};
use std::fmt::Write as _;
use std::path::PathBuf;

/// How the answer came about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    /// Every method decompiled.
    Ok,
    /// The class decompiled, some methods did not (listed in [`Decompiled::failed_methods`]).
    Partial,
    /// Every backend failed on the whole class: the text is smali.
    Smali,
}

impl Status {
    /// `ok`, `partial` or `failed` (the backends failed; smali shown).
    pub fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Partial => "partial",
            Status::Smali => "failed",
        }
    }
}

/// Whether the names in the text are the mapping file's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Naming {
    /// No mapping file: the DEX's own names.
    Dex,
    /// The backend applied the mapping file.
    Unified,
    /// There is a mapping file but the backend takes no mappings, so the
    /// text keeps the DEX's names (asc does not rewrite source, §7).
    NotUnified,
}

/// A backend that was tried and did not answer for the class.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attempt {
    /// The backend's name.
    pub backend: String,
    /// Why it gave no source.
    pub reason: String,
}

/// The answer to a decompile request.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Decompiled {
    /// The class's type descriptor.
    pub class: String,
    /// The outer class whose source the text is, when the class is nested
    /// and the backend folded it into that one (docs/decompile-backends.md §6.3).
    pub folded_into: Option<String>,
    /// The backend that answered, `None` for smali.
    pub backend: Option<String>,
    /// Its version, as `initialize` reported it.
    pub version: Option<String>,
    /// How the answer came about.
    pub status: Status,
    /// The language of [`text`](Self::text); `None` for smali.
    pub language: Option<Language>,
    /// The source (or smali), or only the methods the request picked.
    pub text: String,
    /// Methods the backend failed on (stubs in the text).
    pub failed_methods: Vec<MethodReport>,
    /// The backends tried before, in order, and why each gave nothing.
    pub attempts: Vec<Attempt>,
    /// Served from L3 without asking the backend.
    pub cached: bool,
    /// Whether the names are the mapping file's.
    pub naming: Naming,
    /// The methods picked, when the request named some.
    pub method: Option<String>,
    /// Where `-o DIR` writes the text, relative to `DIR`.
    pub path: PathBuf,
}

impl Decompiled {
    /// The comment marker of the text's language.
    fn comment(&self) -> &'static str {
        if self.status == Status::Smali { "#" } else { "//" }
    }

    /// Lines naming the backend that answered, the status, the backends
    /// that failed before it, the methods that failed and whether names are
    /// unified, as comments of the text's language.
    pub fn header(&self) -> String {
        let c = self.comment();
        let mut out = String::new();
        let by = match (&self.backend, &self.version) {
            (Some(backend), Some(version)) => format!("{backend} {version}"),
            (Some(backend), None) => backend.clone(),
            (None, _) => "smali (no decompiler gave source)".to_string(),
        };
        let cached = if self.cached { ", from cache" } else { "" };
        let folded = self.folded_into.as_ref().map_or_else(String::new, |outer| format!(" | in {outer}"));
        let _ = writeln!(out, "{c} decompile {}{folded} | by {by} | status {}{cached}", self.class, self.status.name());
        for attempt in &self.attempts {
            let _ = writeln!(out, "{c} {} failed: {}", attempt.backend, one_line(&attempt.reason));
        }
        if !self.failed_methods.is_empty() {
            let _ = writeln!(out, "{c} failed methods: {}", self.failed_methods.len());
            for method in &self.failed_methods {
                match &method.reason {
                    Some(reason) => _ = writeln!(out, "{c}   {}: {}", method.signature, one_line(reason)),
                    None => _ = writeln!(out, "{c}   {}", method.signature),
                }
            }
        }
        if self.naming == Naming::NotUnified {
            let backend = self.backend.as_deref().unwrap_or("smali");
            let _ = writeln!(out, "{c} names not unified: {backend} takes no mapping file; names are the DEX's own");
        }
        out
    }

    /// The header and the text.
    pub fn render(&self) -> String {
        let mut out = self.header();
        out.push_str(&self.text);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    /// Whether some or all of the class failed to decompile.
    pub fn is_degraded(&self) -> bool {
        self.status != Status::Ok
    }
}

/// `reason` on one line, cut to a readable length. The middle goes: a
/// crash reads `backend exited: STATUS; stderr: ...` and the last words on
/// stderr say why.
fn one_line(reason: &str) -> String {
    const HEAD: usize = 120;
    const TAIL: usize = 240;
    let line: String = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars = line.chars().count();
    if chars <= HEAD + TAIL {
        return line;
    }
    let head: String = line.chars().take(HEAD).collect();
    let tail: String = line.chars().skip(chars - TAIL).collect();
    format!("{head} ... {tail}")
}

/// The failed methods of a unit's report.
pub(super) fn failed(methods: &[MethodReport]) -> Vec<MethodReport> {
    methods.iter().filter(|method| method.status == MethodStatus::Failed).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Decompiled {
        Decompiled {
            class: "La/Main;".into(),
            folded_into: None,
            backend: Some("jadx".into()),
            version: Some("1.5".into()),
            status: Status::Partial,
            language: Some(Language::Java),
            text: "class Main {}".into(),
            failed_methods: vec![MethodReport::new("run(I)V", MethodStatus::Failed).reason(Some("irreducible\nloop".into()))],
            attempts: vec![Attempt { backend: "dexdec".into(), reason: "backend exited: signal 6".into() }],
            cached: true,
            naming: Naming::NotUnified,
            method: None,
            path: PathBuf::from("a/Main.java"),
        }
    }

    #[test]
    fn header_names_backend_status_failures_and_naming() {
        let text = sample().render();
        assert_eq!(
            text,
            "// decompile La/Main; | by jadx 1.5 | status partial, from cache\n\
             // dexdec failed: backend exited: signal 6\n\
             // failed methods: 1\n\
             //   run(I)V: irreducible loop\n\
             // names not unified: jadx takes no mapping file; names are the DEX's own\n\
             class Main {}\n"
        );
    }

    #[test]
    fn header_names_the_outer_class_of_a_folded_nested_class() {
        let nested = Decompiled { class: "La/Main$1;".into(), folded_into: Some("La/Main;".into()), ..sample() };
        assert!(nested.header().starts_with("// decompile La/Main$1; | in La/Main; | by jadx 1.5 | status partial"), "{}", nested.header());
    }

    #[test]
    fn long_reasons_keep_their_start_and_end() {
        let reason = format!("backend exited: signal 6; stderr: {} memory allocation of 240518168464 bytes failed", "x ".repeat(400));
        let line = one_line(&reason);
        assert!(line.starts_with("backend exited: signal 6; stderr: x x"), "{line}");
        assert!(line.contains(" ... ") && line.ends_with("memory allocation of 240518168464 bytes failed"), "{line}");
        assert_eq!(one_line("a\n  b"), "a b");
    }
}
