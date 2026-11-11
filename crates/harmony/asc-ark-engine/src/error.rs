use std::path::PathBuf;

use thiserror::Error;

/// Errors of the HarmonyOS engine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EngineError {
    /// A file of the program could not be read.
    #[error("io error on {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A file of an unpacked package that is larger than a query reads
    /// into memory: the bound a zip entry has.
    #[error("{} holds {size} bytes, limit {limit}", path.display())]
    FileTooLarge {
        /// The file.
        path: PathBuf,
        /// Its size in bytes.
        size: u64,
        /// The most bytes a query reads, in bytes.
        limit: u64,
    },
    /// A `.hap`, `.hsp` or `.app` archive could not be opened.
    #[error(transparent)]
    Archive(#[from] asc_apk::ApkError),
    /// Nothing under the path holds ABC code; `notes` say what was looked at.
    #[error("no ABC code in {} ({})", path.display(), notes.join("; "))]
    NoCode {
        /// The path the program was opened from.
        path: PathBuf,
        /// One line per place looked at.
        notes: Vec<String>,
    },
    /// No package of the program has the metadata document asked for
    /// (`document`; `None`: any at all). `bare`: the program is only bare
    /// `.abc` files, which never have one.
    #[error("no {} in {}{}", document.unwrap_or("manifest"), path.display(), if *bare { BARE_ABC_HINT } else { "" })]
    NoManifest {
        /// The path the program was opened from.
        path: PathBuf,
        /// The document asked for (`module.json`, `pack.info`…).
        document: Option<&'static str>,
        /// The program is only bare `.abc` files.
        bare: bool,
    },
    /// No package of the program has a `resources.index` that reads;
    /// `notes` say what was looked at.
    #[error("no resources.index in {}{}", path.display(), note_suffix(notes))]
    NoResources {
        /// The path the program was opened from.
        path: PathBuf,
        /// One line per place looked at.
        notes: Vec<String>,
    },
    /// An ABC entry, or a structure inside it, does not parse.
    #[error("{entry}: {source}")]
    Abc {
        /// The ABC entry.
        entry: String,
        /// What the parser rejected.
        source: asc_abc::AbcError,
    },
    /// A regular expression of a query does not compile.
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
    /// A query that does not parse or asks for something that cannot be.
    #[error("{0}")]
    Query(String),
    /// No ABC entry of the program has the given name.
    #[error("no entry named {0}")]
    NoEntry(String),
    /// `notes` name the entries that could not be searched (encrypted ones).
    #[error("{what} {name} not found{}", note_suffix(notes))]
    NotFound {
        /// What was looked for: `record`, `function`, `resource`…
        what: &'static str,
        /// The name asked for.
        name: String,
        /// The entries that could not be searched.
        notes: Vec<String>,
    },
    /// A name matches more than one item, so the query does not pick one.
    #[error("{what} {name} is ambiguous, candidates:\n{}", candidates.join("\n"))]
    Ambiguous {
        /// What was looked for: `record`, `function`…
        what: &'static str,
        /// The name asked for.
        name: String,
        /// The full names of every match.
        candidates: Vec<String>,
    },
    /// A record or function could not be disassembled.
    #[error("disassembly failed: {0}")]
    Disassembly(String),
    /// The caller raised the cancel flag before the work finished.
    #[error("cancelled")]
    Cancelled,
}

const BARE_ABC_HINT: &str = ": a bare .abc carries no module.json; pass the .hap / .app it came from, or a directory holding both";

fn note_suffix(notes: &[String]) -> String {
    if notes.is_empty() { String::new() } else { format!(" ({})", notes.join("; ")) }
}

/// A `Result` whose error is [`EngineError`].
pub type Result<T> = std::result::Result<T, EngineError>;
