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
    /// Every backend failed on the whole HarmonyOS record: the text is its
    /// disassembly, as `getclass` lists it.
    Disassembly,
}

impl Status {
    /// `ok`, `partial` or `failed` (the backends failed; smali or the disassembly shown).
    pub fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Partial => "partial",
            Status::Smali | Status::Disassembly => "failed",
        }
    }

    /// Whether the text is no backend's but asc's own listing.
    pub fn is_listing(self) -> bool {
        matches!(self, Status::Smali | Status::Disassembly)
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
    /// The class's type descriptor, or the HarmonyOS record's name.
    pub class: String,
    /// The ABC entry of a HarmonyOS record (`entry.hap/ets/modules.abc`).
    pub entry: Option<String>,
    /// The outer class whose source the text is, when the class is nested
    /// and the backend folded it into that one (docs/decompile-backends.md §6.3).
    pub folded_into: Option<String>,
    /// The backend that answered, `None` for smali or the disassembly.
    pub backend: Option<String>,
    /// Its version, as `initialize` reported it.
    pub version: Option<String>,
    /// How the answer came about.
    pub status: Status,
    /// The language of [`text`](Self::text); `None` for smali or the disassembly.
    pub language: Option<Language>,
    /// The source (or smali), or only the methods the request picked.
    pub text: String,
    /// Methods the backend failed on (stubs in the text).
    pub failed_methods: Vec<MethodReport>,
    /// Every function the backend reported for a HarmonyOS record: raw and
    /// restored names, structuring level, status. Empty for a DEX class.
    pub functions: Vec<MethodReport>,
    /// More header lines: what asc did about the request, e.g. a method it
    /// could not cut out of the text.
    pub notes: Vec<String>,
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
    pub fn comment(&self) -> &'static str {
        if self.status.is_listing() { "#" } else { "//" }
    }

    /// What the text is when no backend gave it: `smali` or `disassembly`;
    /// `None` when a backend did.
    pub fn listing(&self) -> Option<&'static str> {
        match self.status {
            Status::Smali => Some("smali"),
            Status::Disassembly => Some("disassembly"),
            Status::Ok | Status::Partial => None,
        }
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
            (None, _) => format!("{} (no decompiler gave source)", self.listing().unwrap_or("smali")),
        };
        let cached = if self.cached { ", from cache" } else { "" };
        let folded = self.folded_into.as_ref().map_or_else(String::new, |outer| format!(" | in {outer}"));
        let entry = self.entry.as_ref().map_or_else(String::new, |entry| format!(" | {entry}"));
        let _ = writeln!(out, "{c} decompile {}{entry}{folded} | by {by} | status {}{cached}", self.class, self.status.name());
        for attempt in &self.attempts {
            let _ = writeln!(out, "{c} {} failed: {}", attempt.backend, one_line(&attempt.reason));
        }
        if !self.failed_methods.is_empty() {
            let _ = writeln!(out, "{c} failed methods: {}", self.failed_methods.len());
            for method in &self.failed_methods {
                let name = match &method.restored {
                    Some(restored) if *restored != method.signature => format!("{} ({restored})", method.signature),
                    _ => method.signature.clone(),
                };
                match &method.reason {
                    Some(reason) => _ = writeln!(out, "{c}   {name}: {}", one_line(reason)),
                    None => _ = writeln!(out, "{c}   {name}"),
                }
            }
        }
        for note in &self.notes {
            let _ = writeln!(out, "{c} {}", one_line(note));
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
            entry: None,
            folded_into: None,
            backend: Some("jadx".into()),
            version: Some("1.5".into()),
            status: Status::Partial,
            language: Some(Language::Java),
            text: "class Main {}".into(),
            failed_methods: vec![MethodReport::new("run(I)V", MethodStatus::Failed).reason(Some("irreducible\nloop".into()))],
            functions: Vec::new(),
            notes: Vec::new(),
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
    fn header_of_a_record_names_its_entry_and_restored_names() {
        let failed = MethodReport::new("#~@0>#build", MethodStatus::Failed)
            .restored(Some("Index.build".into()))
            .reason(Some("inexact: contains an operation of unknown semantics".into()));
        let record = Decompiled {
            class: "&entry/src/main/ets/pages/Index&".into(),
            entry: Some("ets/modules.abc".into()),
            backend: Some("arkdec".into()),
            version: Some("0.2.0".into()),
            language: Some(Language::JavaScript),
            failed_methods: vec![failed],
            attempts: Vec::new(),
            cached: false,
            naming: Naming::Dex,
            notes: vec!["arkdec reported no text of #~@0>#build; the whole record follows".into()],
            ..sample()
        };
        assert_eq!(
            record.header(),
            "// decompile &entry/src/main/ets/pages/Index& | ets/modules.abc | by arkdec 0.2.0 | status partial\n\
             // failed methods: 1\n\
             //   #~@0>#build (Index.build): inexact: contains an operation of unknown semantics\n\
             // arkdec reported no text of #~@0>#build; the whole record follows\n"
        );
        let listing = Decompiled {
            backend: None,
            version: None,
            status: Status::Disassembly,
            language: None,
            failed_methods: Vec::new(),
            notes: Vec::new(),
            attempts: vec![Attempt { backend: "arkdec".into(), reason: "asc-arkdec-worker not found".into() }],
            ..record
        };
        assert_eq!(
            listing.header(),
            "# decompile &entry/src/main/ets/pages/Index& | ets/modules.abc | by disassembly (no decompiler gave source) | status failed\n\
             # arkdec failed: asc-arkdec-worker not found\n"
        );
        assert!(listing.is_degraded() && listing.status.is_listing());
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
