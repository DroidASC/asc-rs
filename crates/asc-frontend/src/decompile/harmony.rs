//! JavaScript or ArkTS of a HarmonyOS record ([`Decompilers::decompile_harmony`];
//! docs/decompile-backends.md §6.5, §8, §9).
//!
//! ArkTS (`arkts`) is JavaScript with the ArkUI DSL recovered where the
//! backend can: a record without it comes back as its JavaScript module.
//! The unit's `path` says which (`.ets` / `.js`), and the answer's
//! [`language`](Decompiled::language) and `-o` path follow it.
//!
//! The record is named as `getclass` names it ([`ClassTarget`]): its
//! entry, record and function are located first, so a name that is not
//! there fails before any backend starts. The backend is handed the ABC
//! entry that defines the record, as one file ([`abc_input`](super::abc_input)),
//! and asked for the record. Its answer is cached under the entry's content
//! ([`ApkKey::for_content`]): the same file anywhere hits. When every backend
//! of the chain ([`Settings::chain_for`](super::Settings::chain_for)) fails,
//! the answer is the disassembly `getclass` shows.

use asc_ark_engine::{ClassQuery, Location};
use asc_decompile::Priority;
use asc_decompile::protocol::methods::{Language, ResourceNames, UnitOutcome};
use asc_engine::asc_cache::ApkKey;
use serde_json::{Map, Value};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use super::{
    Answer, Attempt, CallOptions, Context, DecompileError, Decompiled, Decompilers, Input, Naming, Outcome, ProgramResources, Status,
    outcome, source,
};
use crate::format::ProgramFormat;
use crate::harmony::ClassTarget;

/// How far a backend structures control flow (`--level`), when not as far as it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Level {
    /// No structuring: every function as a loop that dispatches on the
    /// program counter (`pcDispatch`), the rung that always works.
    PcDispatch,
}

impl Level {
    /// The level `name` spells: `pc-dispatch` (also `pcDispatch`, `pc_dispatch`), case aside.
    pub fn parse(name: &str) -> Option<Level> {
        match name.trim().to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "pcdispatch" => Some(Level::PcDispatch),
            _ => None,
        }
    }

    /// The value of the `level` request option (§6.5).
    pub fn wire(self) -> &'static str {
        match self {
            Level::PcDispatch => "pcDispatch",
        }
    }
}

/// What to decompile of a HarmonyOS program.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct HarmonyRequest<'a> {
    /// The record, as `getclass` takes it: canonical, a path suffix
    /// (`pages/Index`), or a findrefs location `RECORD->FUNCTION[+0xPC]`.
    pub record: &'a str,
    /// One function of it: raw (`#~@0>#build`), restored (`Index.build`) or a dotted suffix.
    pub method: Option<&'a str>,
    /// The ABC entry the record is in, for a record several entries define.
    pub entry: Option<&'a str>,
    /// The backend to use alone; `None`: the HarmonyOS default, then its fallbacks.
    pub decompiler: Option<&'a str>,
    /// The output language: JavaScript (the default) or ArkTS.
    pub language: Language,
    /// The bytecode as it is, without undoing what the compiler generated (`raw`).
    pub raw: bool,
    /// Structure no further than this.
    pub level: Option<Level>,
    /// Queue lane of the backend requests.
    pub priority: Priority,
    /// How the front end spells the entry argument (`--entry`), for errors.
    pub entry_arg: &'a str,
}

impl<'a> HarmonyRequest<'a> {
    /// JavaScript of `record` from the HarmonyOS chain.
    pub fn new(record: &'a str) -> HarmonyRequest<'a> {
        HarmonyRequest {
            record,
            method: None,
            entry: None,
            decompiler: None,
            language: Language::JavaScript,
            raw: false,
            level: None,
            priority: Priority::Interactive,
            entry_arg: "--entry",
        }
    }

    /// The request with [`method`](#structfield.method) set.
    #[must_use]
    pub fn method(self, method: Option<&'a str>) -> HarmonyRequest<'a> {
        HarmonyRequest { method, ..self }
    }

    /// The request with [`entry`](#structfield.entry) set.
    #[must_use]
    pub fn entry(self, entry: Option<&'a str>) -> HarmonyRequest<'a> {
        HarmonyRequest { entry, ..self }
    }

    /// The request with [`decompiler`](#structfield.decompiler) set.
    #[must_use]
    pub fn decompiler(self, decompiler: Option<&'a str>) -> HarmonyRequest<'a> {
        HarmonyRequest { decompiler, ..self }
    }

    /// The request with [`language`](#structfield.language) set.
    #[must_use]
    pub fn language(self, language: Language) -> HarmonyRequest<'a> {
        HarmonyRequest { language, ..self }
    }

    /// The request with [`raw`](#structfield.raw) set.
    #[must_use]
    pub fn raw(self, raw: bool) -> HarmonyRequest<'a> {
        HarmonyRequest { raw, ..self }
    }

    /// The request with [`level`](#structfield.level) set.
    #[must_use]
    pub fn level(self, level: Option<Level>) -> HarmonyRequest<'a> {
        HarmonyRequest { level, ..self }
    }

    /// The request with [`priority`](#structfield.priority) set.
    #[must_use]
    pub fn priority(self, priority: Priority) -> HarmonyRequest<'a> {
        HarmonyRequest { priority, ..self }
    }

    /// The request with [`entry_arg`](#structfield.entry_arg) set.
    #[must_use]
    pub fn entry_arg(self, entry_arg: &'a str) -> HarmonyRequest<'a> {
        HarmonyRequest { entry_arg, ..self }
    }

    /// The per-request options (§6.5): `raw` and `level`, when asked for.
    fn options(&self) -> Map<String, Value> {
        let mut options = Map::new();
        if self.raw {
            options.insert("raw".into(), Value::Bool(true));
        }
        if let Some(level) = self.level {
            options.insert("level".into(), Value::String(level.wire().into()));
        }
        options
    }
}

impl Decompilers {
    /// Decompiles a record of the HarmonyOS program `engine` reads, or one
    /// function of it. Raising `cancel` aborts it.
    ///
    /// # Errors
    ///
    /// An unknown backend, a language other than JavaScript or ArkTS, a record or
    /// function the program does not have (or several entries do: the text
    /// says to name one with [`entry_arg`](HarmonyRequest::entry_arg)), an
    /// entry that cannot be read, or cancellation. A failing backend is not
    /// an error: the disassembly answers then.
    pub fn decompile_harmony(
        &self,
        engine: &asc_ark_engine::Engine,
        request: &HarmonyRequest<'_>,
        cancel: &AtomicBool,
    ) -> Result<Decompiled, DecompileError> {
        if !matches!(request.language, Language::JavaScript | Language::ArkTs) {
            return Err(DecompileError::WrongFormat(
                "a HarmonyOS record decompiles to javascript or arkts; java and kotlin are for DEX classes".into(),
            ));
        }
        self.check_decompiler(request.decompiler)?;
        let target = ClassTarget::parse(request.record, request.method);
        let location = target
            .locate(engine, request.entry)
            .map_err(|e| DecompileError::Harmony(target.explain(engine, request.entry, &e, request.entry_arg)))?;
        let entry = location.entry.as_str();
        let unreadable = || DecompileError::Harmony(format!("{entry} cannot be read"));
        let bytes = engine.abc(entry).ok_or_else(unreadable)?.bytes();
        let sha256 = engine.entry_sha256(entry).ok_or_else(unreadable)?;
        let chain = self.settings.chain_for(ProgramFormat::Harmony, request.decompiler);
        let outcome = match self.abc_files.file(entry, bytes, sha256, engine.entry_file(entry)) {
            Ok(abc) => {
                let key = ApkKey::for_content(entry, &sha256);
                let mut names = ResourceNames::default();
                names.names = engine.resource_names(entry);
                let resources = ProgramResources::names(names);
                let mut context = Context {
                    unit: &location.record,
                    language: request.language,
                    apk: Some(&key),
                    input: Input::Abc(abc),
                    mappings: None,
                    resources: resources.as_ref(),
                    request: request.options(),
                    options: CallOptions::default().priority(request.priority),
                };
                self.run_chain(&chain, &mut context, cancel)?
            }
            Err(error) => {
                let reason = format!("cannot write {entry} to a file for the backend: {error}");
                Outcome::Failed(chain.iter().map(|name| Attempt { backend: name.to_string(), reason: reason.clone() }).collect())
            }
        };
        let several = engine.has_several_entries();
        match outcome {
            Outcome::Answered { name, answer, attempts } => {
                Ok(record_answer(&name, &answer, attempts, &location, request.language, several))
            }
            Outcome::Failed(attempts) => disassembly(engine, &location, attempts, several),
        }
    }
}

/// The answer of backend `name` for the record at `location`, asked for in
/// `language`; of its function, when there is one, cut out by the
/// function's span.
fn record_answer(
    name: &str,
    answer: &Answer,
    attempts: Vec<Attempt>,
    location: &Location,
    language: Language,
    several: bool,
) -> Decompiled {
    let unit = &answer.unit;
    let status = match unit.outcome {
        UnitOutcome::Partial { .. } => Status::Partial,
        _ => Status::Ok,
    };
    let whole = unit.text().unwrap_or_default();
    let mut notes = Vec::new();
    let mut failed = outcome::failed(&unit.methods);
    let text = match &location.function {
        None => whole,
        Some(raw) => {
            let report = unit.methods.iter().find(|method| method.signature == *raw);
            match report.and_then(|report| report.slice(whole)) {
                Some(text) => {
                    failed.retain(|method| method.signature == *raw);
                    text
                }
                None => {
                    notes.push(format!("{name} reported no text of {raw}; the whole record follows"));
                    whole
                }
            }
        }
    };
    let backend_path = match &unit.outcome {
        UnitOutcome::Ok { path, .. } | UnitOutcome::Partial { path, .. } => path.as_deref(),
        _ => None,
    };
    let (language, path) = text_path(backend_path, &location.record, language);
    Decompiled {
        class: location.record.clone(),
        entry: Some(location.entry.clone()),
        folded_into: None,
        backend: Some(name.to_string()),
        version: Some(answer.capabilities.backend.version.clone()),
        status,
        language: Some(language),
        text: text.to_string(),
        failed_methods: failed,
        functions: unit.methods.clone(),
        notes,
        attempts,
        cached: answer.cached,
        naming: Naming::Dex,
        method: location.function.clone(),
        path: in_entry(&location.entry, path, several),
    }
}

/// The record at `location` (or its function) as `getclass` lists it, when
/// no backend gave source.
fn disassembly(
    engine: &asc_ark_engine::Engine,
    location: &Location,
    attempts: Vec<Attempt>,
    several: bool,
) -> Result<Decompiled, DecompileError> {
    let query = ClassQuery::new(&location.record).function(location.function.as_deref()).entry(Some(&location.entry));
    let mut listing = engine.get_class(&query).map_err(|e| DecompileError::Harmony(e.to_string()))?;
    // As getclass shows it: the resources the code builds named.
    engine.annotate_resource_ids(&mut listing);
    Ok(Decompiled {
        class: location.record.clone(),
        entry: Some(location.entry.clone()),
        folded_into: None,
        backend: None,
        version: None,
        status: Status::Disassembly,
        language: None,
        text: listing.text,
        failed_methods: Vec::new(),
        functions: Vec::new(),
        notes: Vec::new(),
        attempts,
        cached: false,
        naming: Naming::Dex,
        method: location.function.clone(),
        path: in_entry(&location.entry, record_path(&location.record, "pa"), several),
    })
}

/// The language of a unit asked for in `requested` and where `-o` writes
/// it: the backend's `path` when it passes the checks, else one made from
/// `record`. An ArkTS answer is ArkTS only with an `.ets` path; with a `.js`
/// one it is the record's JavaScript (nothing to recover in it). Without a
/// usable path the requested language is taken at its word.
fn text_path(backend: Option<&str>, record: &str, requested: Language) -> (Language, PathBuf) {
    let take = |extension: &str| backend.and_then(|path| source::backend_path(path, extension));
    match requested {
        Language::ArkTs => match (take("ets"), take("js")) {
            (Some(path), _) => (Language::ArkTs, path),
            (None, Some(path)) => (Language::JavaScript, path),
            (None, None) => (Language::ArkTs, record_path(record, "ets")),
        },
        _ => (Language::JavaScript, take("js").unwrap_or_else(|| record_path(record, "js"))),
    }
}

/// `entry/src/main/ets/pages/Index.js` for `&entry/src/main/ets/pages/Index&`:
/// the record's name without the `&` around it and the version after it.
fn record_path(record: &str, extension: &str) -> PathBuf {
    let name = record.strip_prefix('&').map_or(record, |inner| inner.split('&').next().unwrap_or(inner));
    source::output_path(if name.is_empty() { record } else { name }, extension)
}

/// `path` under the directory of `entry` when the program has several
/// entries, whose records may share names.
fn in_entry(entry: &str, path: PathBuf, several: bool) -> PathBuf {
    if !several {
        return path;
    }
    let plain = |segment: &str| {
        let clean: String = segment.chars().map(|c| if matches!(c, '\\' | ':' | '\0') || c.is_control() { '_' } else { c }).collect();
        if clean.is_empty() || clean == "." || clean == ".." { "_".to_string() } else { clean }
    };
    entry.split('/').map(plain).collect::<PathBuf>().join(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn levels_and_options() {
        for name in ["pc-dispatch", "pcDispatch", "PC_DISPATCH"] {
            assert_eq!(Level::parse(name), Some(Level::PcDispatch), "{name}");
        }
        assert_eq!(Level::parse("structured"), None);
        let request = HarmonyRequest::new("pages/Index");
        assert!(request.options().is_empty());
        let options = request.raw(true).level(Some(Level::PcDispatch)).options();
        assert_eq!(Value::Object(options).to_string(), r#"{"level":"pcDispatch","raw":true}"#, "sorted: one cache key per meaning");
    }

    #[test]
    fn arkts_answers_follow_the_path() {
        let record = "&entry/src/main/ets/pages/Index&";
        let ets = Some("entry/src/main/ets/pages/Index.ets");
        let js = Some("entry/src/main/ets/pages/Index.js");
        let path = |p: &str| PathBuf::from(p);
        assert_eq!(text_path(ets, record, Language::ArkTs), (Language::ArkTs, path("entry/src/main/ets/pages/Index.ets")));
        assert_eq!(text_path(js, record, Language::ArkTs), (Language::JavaScript, path("entry/src/main/ets/pages/Index.js")));
        assert_eq!(text_path(None, record, Language::ArkTs), (Language::ArkTs, path("entry/src/main/ets/pages/Index.ets")));
        assert_eq!(text_path(Some("../x.ets"), record, Language::ArkTs).1, path("entry/src/main/ets/pages/Index.ets"), "stays inside");
        assert_eq!(text_path(js, record, Language::JavaScript), (Language::JavaScript, path("entry/src/main/ets/pages/Index.js")));
        assert_eq!(
            text_path(ets, record, Language::JavaScript),
            (Language::JavaScript, path("entry/src/main/ets/pages/Index.js")),
            "javascript never takes an .ets path"
        );
    }

    #[test]
    fn record_paths() {
        assert_eq!(record_path("&entry/src/main/ets/pages/Index&", "js"), Path::new("entry/src/main/ets/pages/Index.js"));
        assert_eq!(record_path("&@ohos/lib/index&1.0.2", "js"), Path::new("@ohos/lib/index.js"));
        assert_eq!(record_path("_GLOBAL", "js"), Path::new("_GLOBAL.js"));
        assert_eq!(record_path("&../x&", "pa"), Path::new("___/x.pa"), "stays inside");
        let path = PathBuf::from("a/B.js");
        assert_eq!(in_entry("entry.hap/ets/modules.abc", path.clone(), false), path);
        assert_eq!(in_entry("entry.hap/ets/modules.abc", path, true), Path::new("entry.hap/ets/modules.abc/a/B.js"));
    }
}
