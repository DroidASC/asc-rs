use std::path::PathBuf;

use thiserror::Error;

/// Errors of the HarmonyOS engine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EngineError {
    #[error("io error on {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    /// A file of an unpacked package that is larger than a query reads
    /// into memory: the bound a zip entry has.
    #[error("{} holds {size} bytes, limit {limit}", path.display())]
    FileTooLarge { path: PathBuf, size: u64, limit: u64 },
    #[error(transparent)]
    Archive(#[from] asc_apk::ApkError),
    /// Nothing under the path holds ABC code; `notes` say what was looked at.
    #[error("no ABC code in {} ({})", path.display(), notes.join("; "))]
    NoCode { path: PathBuf, notes: Vec<String> },
    /// No package of the program has the metadata document asked for
    /// (`document`; `None`: any at all). `bare`: the program is only bare
    /// `.abc` files, which never have one.
    #[error("no {} in {}{}", document.unwrap_or("manifest"), path.display(), if *bare { BARE_ABC_HINT } else { "" })]
    NoManifest { path: PathBuf, document: Option<&'static str>, bare: bool },
    /// No package of the program has a `resources.index` that reads;
    /// `notes` say what was looked at.
    #[error("no resources.index in {}{}", path.display(), note_suffix(notes))]
    NoResources { path: PathBuf, notes: Vec<String> },
    #[error("{entry}: {source}")]
    Abc { entry: String, source: asc_abc::AbcError },
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
    /// A query that does not parse or asks for something that cannot be.
    #[error("{0}")]
    Query(String),
    #[error("no entry named {0}")]
    NoEntry(String),
    /// `notes` name the entries that could not be searched (encrypted ones).
    #[error("{what} {name} not found{}", note_suffix(notes))]
    NotFound { what: &'static str, name: String, notes: Vec<String> },
    #[error("{what} {name} is ambiguous, candidates:\n{}", candidates.join("\n"))]
    Ambiguous { what: &'static str, name: String, candidates: Vec<String> },
    #[error("disassembly failed: {0}")]
    Disassembly(String),
    #[error("cancelled")]
    Cancelled,
}

const BARE_ABC_HINT: &str = ": a bare .abc carries no module.json; pass the .hap / .app it came from, or a directory holding both";

fn note_suffix(notes: &[String]) -> String {
    if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join("; "))
    }
}

pub type Result<T> = std::result::Result<T, EngineError>;
