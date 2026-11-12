//! Typed parameters and results of every protocol method (§6).
//!
//! Each method is an uninhabited marker type implementing [`Method`] or
//! [`NotificationMethod`], tying its wire name to its parameter and result types.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::PathBuf;

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::jsonrpc::RequestId;

/// A request method: its wire name and the shapes of its params and result.
pub trait Method {
    /// The `method` member, e.g. `decompile/classes`.
    const NAME: &'static str;
    /// The shape of `params`.
    type Params: Serialize + DeserializeOwned;
    /// The shape of `result` in a successful response.
    type Result: Serialize + DeserializeOwned;
}

/// A notification method: its wire name and the shape of its params.
pub trait NotificationMethod {
    /// The `method` member, e.g. `notifications/progress`.
    const NAME: &'static str;
    /// The shape of `params`.
    type Params: Serialize + DeserializeOwned;
}

/// `→ initialize`: the first message on a new connection.
pub enum Initialize {}

impl Method for Initialize {
    const NAME: &'static str = "initialize";
    type Params = InitializeParams;
    type Result = InitializeResult;
}

/// `→ notifications/initialized`: sent after the `initialize` response, before any other request.
pub enum Initialized {}

impl NotificationMethod for Initialized {
    const NAME: &'static str = "notifications/initialized";
    type Params = Empty;
}

impl Initialized {
    /// The bare name used in the design document; servers should accept both.
    pub const LEGACY_NAME: &'static str = "initialized";
}

/// `→ program/open`: loads a program and returns a session id.
pub enum ProgramOpen {}

impl Method for ProgramOpen {
    const NAME: &'static str = "program/open";
    type Params = ProgramOpenParams;
    type Result = ProgramOpenResult;
}

/// `→ program/close`: releases a program session.
pub enum ProgramClose {}

impl Method for ProgramClose {
    const NAME: &'static str = "program/close";
    type Params = ProgramCloseParams;
    type Result = Empty;
}

/// `→ decompile/classes`: decompiles classes of an open program.
pub enum DecompileClasses {}

impl Method for DecompileClasses {
    const NAME: &'static str = "decompile/classes";
    type Params = DecompileClassesParams;
    type Result = DecompileClassesResult;
}

/// `→ shutdown`: asks the backend to get ready to exit; stdin is closed after the response.
pub enum Shutdown {}

impl Method for Shutdown {
    const NAME: &'static str = "shutdown";
    type Params = Empty;
    type Result = Empty;
}

/// `↔ notifications/cancelled`: asks the receiver to abort a request.
pub enum Cancelled {}

impl NotificationMethod for Cancelled {
    const NAME: &'static str = "notifications/cancelled";
    type Params = CancelledParams;
}

/// `← notifications/progress`: progress of a request that carried a `progressToken`.
pub enum Progress {}

impl NotificationMethod for Progress {
    const NAME: &'static str = "notifications/progress";
    type Params = ProgressParams;
}

/// An empty object; also reads `null`, which some JSON-RPC servers return for "no result".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Empty {}

impl<'de> Deserialize<'de> for Empty {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<IgnoredAny>::deserialize(deserializer).map(|_| Self {})
    }
}

/// Name and version of either end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Implementation {
    /// `name`, e.g. `asc` or `jeb`; part of the result cache key.
    pub name: String,
    /// `version`, free-form; part of the result cache key.
    pub version: String,
}

impl Implementation {
    /// The end called `name`, at `version`.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Implementation {
        Implementation { name: name.into(), version: version.into() }
    }
}

/// Params of [`Initialize`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct InitializeParams {
    /// The highest version the client speaks.
    pub protocol_version: u32,
    /// `client`: who is asking, normally asc itself.
    pub client: Implementation,
    /// The `options` table of the backend's configuration, passed through uninterpreted.
    #[serde(default)]
    pub options: Map<String, Value>,
}

impl InitializeParams {
    /// `client` speaking at most `protocol_version`, with no backend options.
    pub fn new(protocol_version: u32, client: Implementation) -> InitializeParams {
        InitializeParams { protocol_version, client, options: Map::new() }
    }

    /// These parameters with the backend's `options` table.
    #[must_use]
    pub fn options(self, options: Map<String, Value>) -> InitializeParams {
        InitializeParams { options, ..self }
    }
}

/// Result of [`Initialize`]: what the backend is and what it can do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct InitializeResult {
    /// The highest version the backend supports that is not above the client's.
    pub protocol_version: u32,
    /// `backend`: the backend's name and version.
    pub backend: Implementation,
    /// Hash of the effective options and output-affecting configuration; part of the cache key.
    pub options_hash: String,
    /// Accepted program inputs. Unknown kinds are dropped when reading.
    #[serde(deserialize_with = "known_only")]
    pub inputs: Vec<InputKind>,
    /// Output languages. Unknown languages are dropped when reading.
    #[serde(deserialize_with = "known_only")]
    pub languages: Vec<Language>,
    /// Whether `program/open` honours `mappings`.
    #[serde(default)]
    pub mappings: bool,
    /// Whether units report per-method failures.
    #[serde(default)]
    pub method_status: bool,
    /// How many `decompile/classes` one process handles at once.
    #[serde(default = "one")]
    pub max_concurrency: NonZeroU32,
    /// Platform classpath the backend ships with; a hint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

impl InitializeResult {
    /// `backend` at `protocol_version` with `options_hash`, accepting no
    /// input and writing no language yet; no mappings, no per-method
    /// status, one request at a time, no platform.
    pub fn new(protocol_version: u32, backend: Implementation, options_hash: impl Into<String>) -> InitializeResult {
        InitializeResult {
            protocol_version,
            backend,
            options_hash: options_hash.into(),
            inputs: Vec::new(),
            languages: Vec::new(),
            mappings: false,
            method_status: false,
            max_concurrency: one(),
            platform: None,
        }
    }

    /// This result accepting the program `inputs`.
    #[must_use]
    pub fn inputs(self, inputs: Vec<InputKind>) -> InitializeResult {
        InitializeResult { inputs, ..self }
    }

    /// This result writing `languages`.
    #[must_use]
    pub fn languages(self, languages: Vec<Language>) -> InitializeResult {
        InitializeResult { languages, ..self }
    }

    /// This result honouring `mappings` in `program/open`, or not.
    #[must_use]
    pub fn mappings(self, mappings: bool) -> InitializeResult {
        InitializeResult { mappings, ..self }
    }

    /// This result reporting per-method failures, or not.
    #[must_use]
    pub fn method_status(self, method_status: bool) -> InitializeResult {
        InitializeResult { method_status, ..self }
    }

    /// This result handling `max_concurrency` requests at once.
    #[must_use]
    pub fn max_concurrency(self, max_concurrency: NonZeroU32) -> InitializeResult {
        InitializeResult { max_concurrency, ..self }
    }

    /// This result shipping the `platform` classpath.
    #[must_use]
    pub fn platform(self, platform: Option<String>) -> InitializeResult {
        InitializeResult { platform, ..self }
    }

    /// Whether the backend declared it accepts `kind` in `inputs`.
    pub fn accepts(&self, kind: InputKind) -> bool {
        self.inputs.contains(&kind)
    }

    /// Whether the backend declared it writes `language` in `languages`.
    pub fn supports(&self, language: Language) -> bool {
        self.languages.contains(&language)
    }
}

fn one() -> NonZeroU32 {
    NonZeroU32::MIN
}

/// Reads a list of enum values, skipping the ones this version does not know, so a
/// backend newer than asc can still be used for what both understand.
fn known_only<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let values = Vec::<Value>::deserialize(deserializer)?;
    Ok(values.into_iter().filter_map(|value| T::deserialize(value).ok()).collect())
}

/// Form of the program handed to a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum InputKind {
    /// The original APK / jar / DEX files.
    Archive,
    /// A closure slice written by asc (`rebuild-slice.md`).
    Slice,
}

/// Source language of the decompiled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Language {
    /// `java`.
    Java,
    /// `kotlin`.
    Kotlin,
}

/// Params of [`ProgramOpen`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProgramOpenParams {
    /// `input`: the program files to load.
    pub input: ProgramInput,
    /// Names asc wants in the output; only sent to backends declaring `mappings`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Mappings>,
}

impl ProgramOpenParams {
    /// Open `input`, with no mappings.
    pub fn new(input: ProgramInput) -> ProgramOpenParams {
        ProgramOpenParams { input, mappings: None }
    }

    /// These parameters with the names asc wants in the output.
    #[must_use]
    pub fn mappings(self, mappings: Option<Mappings>) -> ProgramOpenParams {
        ProgramOpenParams { mappings, ..self }
    }
}

/// The program to open, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[non_exhaustive]
pub enum ProgramInput {
    /// Original program files analysed together as one program.
    Archive {
        /// `files`: APK, jar or DEX paths.
        files: Vec<PathBuf>,
    },
    /// Content-addressed slice files under the asc cache; read-only for the backend.
    Slice {
        /// `files`: the slice's DEX paths.
        files: Vec<PathBuf>,
        /// `manifest`: the role of each class in the slice.
        manifest: SliceManifest,
    },
}

impl ProgramInput {
    /// The `kind` tag of this input.
    pub fn kind(&self) -> InputKind {
        match self {
            Self::Archive { .. } => InputKind::Archive,
            Self::Slice { .. } => InputKind::Slice,
        }
    }

    /// The program files, whatever the kind.
    pub fn files(&self) -> &[PathBuf] {
        match self {
            Self::Archive { files } | Self::Slice { files, .. } => files,
        }
    }
}

/// Roles of the classes in a slice, as type descriptors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SliceManifest {
    /// Classes the request is about.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Classes kept whole because a target needs them (nested classes and the like).
    #[serde(default)]
    pub attached: Vec<String>,
    /// Classes kept only as declarations; never output, and their bodies are not real.
    #[serde(default)]
    pub shells: Vec<String>,
}

/// Renames in asc's member notation (the one `findrefs` prints), applied as user renames.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Mappings {
    /// Class descriptor → new simple or qualified name.
    #[serde(default)]
    pub classes: BTreeMap<String, String>,
    /// `Lowner;->name:Type` → new name.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// `Lowner;->name(Args)Ret` → new name.
    #[serde(default)]
    pub methods: BTreeMap<String, String>,
}

impl Mappings {
    /// Whether no class, field or method is renamed.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.fields.is_empty() && self.methods.is_empty()
    }
}

/// A backend-chosen program session id, valid only on the process that issued it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProgramId(pub String);

/// Result of [`ProgramOpen`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProgramOpenResult {
    /// `programId`: the new session, used by later requests.
    pub program_id: ProgramId,
}

impl ProgramOpenResult {
    /// The session the backend opened, `program_id`.
    pub fn new(program_id: ProgramId) -> ProgramOpenResult {
        ProgramOpenResult { program_id }
    }
}

/// Params of [`ProgramClose`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProgramCloseParams {
    /// `programId`: the session to release.
    pub program_id: ProgramId,
}

impl ProgramCloseParams {
    /// Close the session `program_id`.
    pub fn new(program_id: ProgramId) -> ProgramCloseParams {
        ProgramCloseParams { program_id }
    }
}

/// Token tying `notifications/progress` to the request that asked for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProgressToken {
    /// A numeric token.
    Number(i64),
    /// A string token.
    String(String),
}

impl From<RequestId> for ProgressToken {
    fn from(id: RequestId) -> Self {
        match id {
            RequestId::Number(id) => Self::Number(id),
            RequestId::String(id) => Self::String(id),
        }
    }
}

/// Params of [`DecompileClasses`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DecompileClassesParams {
    /// `programId`: the open session holding the classes.
    pub program_id: ProgramId,
    /// Type descriptors, e.g. `Lbin/mt/json/JSONObject;`.
    pub classes: Vec<String>,
    /// `language`: one of the backend's declared `languages`.
    pub language: Language,
    /// Fold inner and anonymous classes into their outer class.
    #[serde(default = "yes")]
    pub nested: bool,
    /// `progressToken`: when present, the backend may send `notifications/progress` under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_token: Option<ProgressToken>,
}

impl DecompileClassesParams {
    /// `classes` of `program_id` in `language`, nested classes folded in, no
    /// progress asked for.
    pub fn new(program_id: ProgramId, classes: Vec<String>, language: Language) -> DecompileClassesParams {
        DecompileClassesParams { program_id, classes, language, nested: true, progress_token: None }
    }

    /// These parameters folding nested classes into their outer class, or not.
    #[must_use]
    pub fn nested(self, nested: bool) -> DecompileClassesParams {
        DecompileClassesParams { nested, ..self }
    }

    /// These parameters asking for progress under `progress_token`.
    #[must_use]
    pub fn progress_token(self, progress_token: Option<ProgressToken>) -> DecompileClassesParams {
        DecompileClassesParams { progress_token, ..self }
    }
}

fn yes() -> bool {
    true
}

/// Result of [`DecompileClasses`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DecompileClassesResult {
    /// `units`: one per requested class.
    pub units: Vec<ClassUnit>,
}

impl DecompileClassesResult {
    /// The output of each requested class.
    pub fn new(units: Vec<ClassUnit>) -> DecompileClassesResult {
        DecompileClassesResult { units }
    }
}

/// The output for one requested class. A failed class does not fail the batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ClassUnit {
    /// Type descriptor of the class the unit is the source of: the requested
    /// class, or with `nested` the class a requested nested class is folded
    /// into (listed in [`nested_classes`](Self::nested_classes) then).
    pub class: String,
    /// `status` with `path` and `text`, or `reason`, flattened into the unit.
    #[serde(flatten)]
    pub outcome: UnitOutcome,
    /// Per-method status; every failed method must be listed, stubs included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<MethodReport>,
    /// `diagnostics`: backend messages about the class or its methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    /// Source line → (method, dex pc) correspondence, when the backend has it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<LineMapping>,
    /// `nestedClasses`: descriptors of the nested classes folded into the
    /// text, at any depth. Empty when the backend does not say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_classes: Vec<String>,
}

impl ClassUnit {
    /// The `outcome` for `class`, with no method report, diagnostic or line
    /// mapping.
    pub fn new(class: impl Into<String>, outcome: UnitOutcome) -> ClassUnit {
        ClassUnit {
            class: class.into(),
            outcome,
            methods: Vec::new(),
            diagnostics: Vec::new(),
            lines: Vec::new(),
            nested_classes: Vec::new(),
        }
    }

    /// This unit with its per-method status.
    #[must_use]
    pub fn methods(self, methods: Vec<MethodReport>) -> ClassUnit {
        ClassUnit { methods, ..self }
    }

    /// This unit with `diagnostics`.
    #[must_use]
    pub fn diagnostics(self, diagnostics: Vec<Diagnostic>) -> ClassUnit {
        ClassUnit { diagnostics, ..self }
    }

    /// This unit with its source line to method correspondence.
    #[must_use]
    pub fn lines(self, lines: Vec<LineMapping>) -> ClassUnit {
        ClassUnit { lines, ..self }
    }

    /// This unit with the nested classes folded into its text.
    #[must_use]
    pub fn nested_classes(self, nested_classes: Vec<String>) -> ClassUnit {
        ClassUnit { nested_classes, ..self }
    }

    /// Whether the unit's text shows `class`: it is the unit's class or one
    /// of its nested classes.
    pub fn covers(&self, class: &str) -> bool {
        self.class == class || self.nested_classes.iter().any(|nested| nested == class)
    }

    /// The `status` member of this unit.
    pub fn status(&self) -> UnitStatus {
        match self.outcome {
            UnitOutcome::Ok { .. } => UnitStatus::Ok,
            UnitOutcome::Partial { .. } => UnitStatus::Partial,
            UnitOutcome::Failed { .. } => UnitStatus::Failed,
        }
    }

    /// The source text, absent when the class failed.
    pub fn text(&self) -> Option<&str> {
        match &self.outcome {
            UnitOutcome::Ok { text, .. } | UnitOutcome::Partial { text, .. } => Some(text),
            UnitOutcome::Failed { .. } => None,
        }
    }
}

/// `status` with the members that depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
#[non_exhaustive]
pub enum UnitOutcome {
    /// `ok`: every method decompiled.
    Ok {
        /// Suggested relative path; for display only, never used to write files.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// The source text.
        text: String,
    },
    /// Some methods failed; they are listed in [`ClassUnit::methods`].
    Partial {
        /// Suggested relative path; for display only, never used to write files.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// The source text, failed methods included as stubs.
        text: String,
    },
    /// `failed`: no text for the class.
    Failed {
        /// Why the class failed.
        reason: String,
    },
}

/// [`UnitOutcome`] without its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum UnitStatus {
    /// `ok`.
    Ok,
    /// `partial`.
    Partial,
    /// `failed`.
    Failed,
}

/// An entry of `methods`: how one method of a class came out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MethodReport {
    /// `name(Args)Ret`, without the owner.
    pub signature: String,
    /// `status`: whether the method decompiled.
    pub status: MethodStatus,
    /// `reason`: why the method failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MethodReport {
    /// The method `signature` (`name(Args)Ret`) and its `status`, with no reason.
    pub fn new(signature: impl Into<String>, status: MethodStatus) -> MethodReport {
        MethodReport { signature: signature.into(), status, reason: None }
    }

    /// This report saying why.
    #[must_use]
    pub fn reason(self, reason: Option<String>) -> MethodReport {
        MethodReport { reason, ..self }
    }
}

/// Outcome of one method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MethodStatus {
    /// `ok`.
    Ok,
    /// `failed`: the text holds a stub, or nothing, for this method.
    Failed,
}

/// An entry of `diagnostics`: a backend message about a class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Diagnostic {
    /// `severity`.
    pub severity: Severity,
    /// `message`: human-readable text.
    pub message: String,
    /// `method`: `name(Args)Ret` of the method concerned; absent for the whole class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

impl Diagnostic {
    /// `message` at `severity`, about the whole class.
    pub fn new(severity: Severity, message: impl Into<String>) -> Diagnostic {
        Diagnostic { severity, message: message.into(), method: None }
    }

    /// This diagnostic about one `method` (`name(Args)Ret`).
    #[must_use]
    pub fn method(self, method: Option<String>) -> Diagnostic {
        Diagnostic { method, ..self }
    }
}

/// How serious a [`Diagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Severity {
    /// `error`.
    Error,
    /// `warning`.
    Warning,
    /// `info`.
    Info,
}

/// An entry of `lines`: where a source line comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LineMapping {
    /// 1-based line in [`UnitOutcome`]'s `text`.
    pub line: u32,
    /// `name(Args)Ret` of the method the line belongs to.
    pub method: String,
    /// `pc`: dex pc in the method's code, in 16-bit code units.
    pub pc: u32,
}

impl LineMapping {
    /// Source `line` (from 1) comes from `method` at dex `pc`.
    pub fn new(line: u32, method: impl Into<String>, pc: u32) -> LineMapping {
        LineMapping { line, method: method.into(), pc }
    }
}

/// Params of [`Cancelled`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CancelledParams {
    /// `requestId`: the request to abort.
    pub request_id: RequestId,
    /// `reason`: why, for logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl CancelledParams {
    /// Cancel `request_id`, giving no reason.
    pub fn new(request_id: RequestId) -> CancelledParams {
        CancelledParams { request_id, reason: None }
    }

    /// These parameters saying why.
    #[must_use]
    pub fn reason(self, reason: Option<String>) -> CancelledParams {
        CancelledParams { reason, ..self }
    }
}

/// Params of [`Progress`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProgressParams {
    /// `progressToken`: the token of the request making progress.
    pub progress_token: ProgressToken,
    /// `progress`: work done so far, in the same unit as `total`.
    pub progress: f64,
    /// `total`: the amount of work, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// `message`: a short status to show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProgressParams {
    /// `progress` made on the request of `progress_token`, of no known total.
    pub fn new(progress_token: ProgressToken, progress: f64) -> ProgressParams {
        ProgressParams { progress_token, progress, total: None, message: None }
    }

    /// This progress out of `total`.
    #[must_use]
    pub fn total(self, total: Option<f64>) -> ProgressParams {
        ProgressParams { total, ..self }
    }

    /// This progress with a `message` to show.
    #[must_use]
    pub fn message(self, message: Option<String>) -> ProgressParams {
        ProgressParams { message, ..self }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn initialize_result_matches_document() {
        let result: InitializeResult = serde_json::from_value(json!({
            "protocolVersion": 1,
            "backend": {"name": "jeb", "version": "5.20.0"},
            "optionsHash": "9f2c",
            "inputs": ["slice", "remote"],
            "languages": ["java", "smali"],
            "mappings": true,
            "methodStatus": true,
            "maxConcurrency": 1,
            "platform": "android-35"
        }))
        .unwrap();
        assert_eq!(result.inputs, [InputKind::Slice], "unknown input kinds are dropped");
        assert_eq!(result.languages, [Language::Java]);
        assert!(result.accepts(InputKind::Slice) && !result.accepts(InputKind::Archive));
        assert_eq!(result.max_concurrency.get(), 1);

        let minimal: InitializeResult = serde_json::from_value(json!({
            "protocolVersion": 1, "backend": {"name": "x", "version": "0"},
            "optionsHash": "", "inputs": ["archive"], "languages": ["java"]
        }))
        .unwrap();
        assert!(!minimal.mappings && !minimal.method_status);
        assert_eq!(minimal.max_concurrency.get(), 1);

        let zero = json!({
            "protocolVersion": 1, "backend": {"name": "x", "version": "0"},
            "optionsHash": "", "inputs": [], "languages": [], "maxConcurrency": 0
        });
        assert!(serde_json::from_value::<InitializeResult>(zero).is_err());
    }

    #[test]
    fn program_open_matches_document() {
        let wire = json!({
            "input": {"kind": "slice", "files": ["/c/3a7f.dex"],
                      "manifest": {"targets": ["La;"], "attached": ["La$M;"], "shells": ["Lb;"]}},
            "mappings": {"classes": {"Ll/x;": "LinkedTable"}, "fields": {"La;->a:I": "size"}, "methods": {}}
        });
        let params: ProgramOpenParams = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(params.input.kind(), InputKind::Slice);
        assert_eq!(params.input.files(), [PathBuf::from("/c/3a7f.dex")]);
        assert_eq!(serde_json::to_value(&params).unwrap(), wire);

        let archive = ProgramOpenParams { input: ProgramInput::Archive { files: vec!["/a.apk".into()] }, mappings: None };
        assert_eq!(serde_json::to_value(&archive).unwrap(), json!({"input": {"kind": "archive", "files": ["/a.apk"]}}));
    }

    #[test]
    fn decompile_result_matches_document() {
        let wire = json!({"units": [{
            "class": "Lbin/mt/json/JSONObject;",
            "status": "partial",
            "path": "bin/mt/json/JSONObject.java",
            "text": "package bin.mt.json;\n",
            "methods": [{"signature": "toString()Ljava/lang/String;", "status": "failed",
                         "reason": "region recovery: irreducible loop"}],
            "diagnostics": [{"severity": "warning", "message": "m", "method": "f()V"}],
            "lines": [{"line": 120, "method": "put(Ljava/lang/String;I)Lbin/mt/json/JSONObject;", "pc": 4}],
            "nestedClasses": ["Lbin/mt/json/JSONObject$Member;"]
        }, {
            "class": "La;", "status": "failed", "reason": "boom"
        }]});
        let result: DecompileClassesResult = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(result.units[0].status(), UnitStatus::Partial);
        assert_eq!(result.units[0].text(), Some("package bin.mt.json;\n"));
        assert_eq!(result.units[1].outcome, UnitOutcome::Failed { reason: "boom".into() });
        assert!(result.units[0].covers("Lbin/mt/json/JSONObject$Member;") && result.units[0].covers("Lbin/mt/json/JSONObject;"));
        assert!(result.units[1].nested_classes.is_empty() && !result.units[1].covers("La$1;"), "nestedClasses is optional");
        assert_eq!(serde_json::to_value(&result).unwrap(), wire);

        let no_reason = json!({"units": [{"class": "La;", "status": "failed"}]});
        assert!(serde_json::from_value::<DecompileClassesResult>(no_reason).is_err(), "failed requires reason");
        let no_text = json!({"units": [{"class": "La;", "status": "ok"}]});
        assert!(serde_json::from_value::<DecompileClassesResult>(no_text).is_err(), "ok requires text");
    }

    #[test]
    fn decompile_params_default_nested() {
        let params: DecompileClassesParams =
            serde_json::from_value(json!({"programId": "p1", "classes": ["La;"], "language": "java"})).unwrap();
        assert!(params.nested);
        assert_eq!(params.progress_token, None);
    }

    #[test]
    fn notifications_use_camel_case() {
        let cancelled = CancelledParams { request_id: 3.into(), reason: None };
        assert_eq!(serde_json::to_value(&cancelled).unwrap(), json!({"requestId": 3}));
        let progress: ProgressParams = serde_json::from_value(json!({"progressToken": "t3", "progress": 0, "total": 1})).unwrap();
        assert_eq!(progress.progress_token, ProgressToken::String("t3".into()));
    }

    #[test]
    fn empty_accepts_null_and_objects() {
        assert_eq!(serde_json::from_value::<Empty>(Value::Null).unwrap(), Empty {});
        assert_eq!(serde_json::from_value::<Empty>(json!({"x": 1})).unwrap(), Empty {});
        assert_eq!(serde_json::to_value(Empty {}).unwrap(), json!({}));
    }
}
