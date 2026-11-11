//! What both front ends make of HarmonyOS arguments and answers: the target
//! of `getclass`, the search kinds of `findrefs`, function spellings as call
//! graph roots, name patterns, call trees as rows, and the hints of an empty
//! answer. Each front end passes how it spells a search
//! (`findrefs call` on the command line, `findrefs kind=call` in MCP), so the
//! hints read right in both.

use asc_ark_engine::{
    Access, CallNode, CallRoots, CallTree, ClassQuery, ClassSource, Direction, Engine, EngineError, ListingStyle, Pattern, Query,
};
use std::path::Path;

/// ABC entries a list of them names ([`entries_hint`]) before it counts the rest.
pub const MAX_ENTRIES_LISTED: usize = 12;

/// Bytes of function headers [`function_list`] lists before it counts the rest.
const MAX_FUNCTIONS_LISTED: usize = 2 << 10;

/// What `getclass` is asked for: a record, or one function of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassTarget<'a> {
    record: &'a str,
    function: Option<&'a str>,
}

impl<'a> ClassTarget<'a> {
    /// `class` with `method`, or the location column of a findrefs row
    /// pasted as the class: `RECORD->FUNCTION` or `RECORD->FUNCTION+0xPC`.
    pub fn parse(class: &'a str, method: Option<&'a str>) -> ClassTarget<'a> {
        if method.is_some() {
            return ClassTarget { record: class, function: method };
        }
        match class.split_once("->") {
            Some((record, function)) => ClassTarget { record, function: Some(function) },
            None => ClassTarget { record: class, function: None },
        }
    }

    /// The record, as given.
    pub fn record(&self) -> &'a str {
        self.record
    }

    /// The function, as given (a `+0xPC` included).
    pub fn function(&self) -> Option<&'a str> {
        self.function
    }

    /// The listing of the target in `entry` (any entry when `None`). A
    /// function is looked up as written first, then, if no function has
    /// that name, without the `+0xPC` of a findrefs row.
    ///
    /// # Errors
    /// As [`Engine::get_class_as`]; [`ClassTarget::explain`] says them the
    /// way both front ends do.
    pub fn listing(&self, engine: &Engine, entry: Option<&str>, style: ListingStyle) -> Result<ClassSource, EngineError> {
        let get = |function: Option<&str>| engine.get_class_as(&ClassQuery::new(self.record).function(function).entry(entry), style);
        match get(self.function) {
            Err(EngineError::NotFound { what: "function", .. }) if self.function.is_some_and(|f| without_pc(f) != f) => {
                get(self.function.map(without_pc))
            }
            other => other,
        }
    }

    /// The text of an error of [`ClassTarget::listing`]: an ambiguous record
    /// says to name its entry (`entry_arg`: how the front end spells that
    /// argument), a function the record lacks lists the ones it has.
    pub fn explain(&self, engine: &Engine, entry: Option<&str>, error: &EngineError, entry_arg: &str) -> String {
        match error {
            EngineError::Ambiguous { candidates, .. } if several_entries_define(candidates) => {
                format!("{error}\n(name the entry, the first column, with {entry_arg})")
            }
            EngineError::NotFound { what: "function", .. } => {
                match engine.get_class_as(&ClassQuery::new(self.record).entry(entry), ListingStyle::default()) {
                    Ok(whole) => format!("{error}; its functions: {}", function_list(&whole.text)),
                    Err(_) => error.to_string(),
                }
            }
            _ => error.to_string(),
        }
    }
}

/// `#~@0>#build (Index.build), ...`: the functions of the record a listing
/// disassembles, at most about [`MAX_FUNCTIONS_LISTED`] bytes of them.
fn function_list(source: &str) -> String {
    let mut headers = source.lines().filter_map(|line| line.strip_prefix(".function "));
    let mut out = String::new();
    while let Some(header) = headers.next() {
        if out.len() + header.len() > MAX_FUNCTIONS_LISTED {
            out.push_str(&format!("... {} more", 1 + headers.count()));
            break;
        }
        match header.split_once("  ; ") {
            Some((raw, restored)) => out.push_str(&format!("{raw} ({restored}), ")),
            None => out.push_str(&format!("{header}, ")),
        }
    }
    out.trim_end_matches(", ").to_owned()
}

/// What one search kind of `findrefs` is given beyond the kind: the value
/// and the flags that refine it. A flag a kind does not read is ignored;
/// each front end rejects the ones it does not allow.
#[derive(Debug, Clone, Copy, Default)]
pub struct SearchArgs<'a> {
    value: &'a str,
    literal: bool,
    exact: bool,
    access: Option<Access>,
    declarations_only: bool,
    dir: Option<&'a Path>,
}

impl<'a> SearchArgs<'a> {
    /// `value` with every flag off.
    pub fn new(value: &'a str) -> SearchArgs<'a> {
        SearchArgs { value, ..SearchArgs::default() }
    }

    /// The value is plain text, not a regex (`string`, `prop`, `global`,
    /// `import`, `call`).
    #[must_use]
    pub fn literal(self, literal: bool) -> Self {
        SearchArgs { literal, ..self }
    }

    /// A name is the whole name, not a regex (`prop`, `global`, `method`).
    #[must_use]
    pub fn exact(self, exact: bool) -> Self {
        SearchArgs { exact, ..self }
    }

    /// How a property or global is used (`prop`, `global`).
    #[must_use]
    pub fn access(self, access: Option<Access>) -> Self {
        SearchArgs { access, ..self }
    }

    /// The import declarations only, not their uses (`import`).
    #[must_use]
    pub fn declarations_only(self, declarations_only: bool) -> Self {
        SearchArgs { declarations_only, ..self }
    }

    /// The directory `call:{@FILE}` reads `FILE` relative to (the current
    /// directory when `None`).
    #[must_use]
    pub fn dir(self, dir: Option<&'a Path>) -> Self {
        SearchArgs { dir, ..self }
    }

    /// The name of a property or a global, as a condition spells it.
    fn name(&self) -> Result<Pattern, EngineError> {
        name_pattern(self.value, self.literal, self.exact)
    }
}

/// One kind of reference `findrefs` searches a HarmonyOS program for, as
/// both front ends read its arguments. A kind the engine learns is one more
/// row of [`SearchKind::ALL`].
#[derive(Debug)]
pub struct SearchKind {
    name: &'static str,
    query: fn(&SearchArgs<'_>) -> Result<Query, EngineError>,
    usage: &'static str,
}

impl SearchKind {
    /// Every kind, in the order a usage text lists them.
    pub const ALL: &'static [SearchKind] = &[
        SearchKind {
            name: "string",
            query: |args| if args.literal { Ok(Query::string_literal(args.value)) } else { Query::string_regex(args.value) },
            usage: "regex (literal=true: text)",
        },
        SearchKind { name: "literal", query: |args| Ok(Query::string_literal(args.value)), usage: "text" },
        SearchKind {
            name: "prop",
            query: |args| Ok(Query::Prop { name: args.name()?, access: args.access }),
            usage: "property name regex (exact / literal), access=read|write|define|call",
        },
        SearchKind {
            name: "global",
            query: |args| Query::global(args.name()?, args.access),
            usage: "global name regex (exact / literal), access=read|write",
        },
        SearchKind {
            name: "import",
            query: |args| match Query::import(args.value, args.literal)? {
                Query::Import { request, name, .. } => Ok(Query::Import { request, name, declarations_only: args.declarations_only }),
                other => Ok(other),
            },
            usage: "REQUEST[#NAME], REQUEST a regex over the module request (@ohos:net.http), decl=true for the declarations \
                    only, requests=true for the distinct requests",
        },
        SearchKind {
            name: "method",
            query: |args| Query::method(without_pc(args.value), |name| name_pattern(name, false, args.exact)),
            usage: "[RECORD->]FUNCTION, where it is defined (or `class` + `name`; exact)",
        },
        SearchKind { name: "number", query: |args| Ok(Query::Number(args.value.parse()?)), usage: "1919810, 0x1d4b42, 1.5 or A..B" },
        SearchKind {
            name: "call",
            query: |args| match (args.literal, args.value.starts_with('{')) {
                (true, _) => Ok(Query::Call(Pattern::contains(args.value))),
                (false, true) => match Query::rule(&format!("call:{}", args.value), args.dir)? {
                    Query::All(_) => Err(EngineError::Query(format!("call:{} is several conditions; give one here", args.value))),
                    query => Ok(query),
                },
                (false, false) => Ok(Query::Call(Pattern::regex(args.value)?)),
            },
            usage: "regex over the resolved callee (import:@ohos:net.http#default.createHttp, global:console.log, this.x), or \
                    {RULE}: the calls that lead to a function RULE matches (call:{string:token}; nests)",
        },
    ];

    /// The kind `kind` names, in any spelling [`Query::kind_named`] reads.
    pub fn named(kind: &str) -> Option<&'static SearchKind> {
        let name = Query::kind_named(kind)?;
        SearchKind::ALL.iter().find(|known| known.name == name)
    }

    /// The kind as `findrefs KIND` and `KIND:VALUE` conditions spell it:
    /// one of [`Query::KINDS`].
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// What the value of this kind is, for a usage text.
    pub fn usage(&self) -> &'static str {
        self.usage
    }

    /// The query this kind asks for with `args`.
    ///
    /// # Errors
    /// [`EngineError::Query`] for a value the kind cannot read (an invalid
    /// regex, a number that is none, a `{RULE}` that is several).
    pub fn query(&self, args: &SearchArgs<'_>) -> Result<Query, EngineError> {
        (self.query)(args)
    }
}

/// `function` without the `+0xPC` a findrefs row appends to it.
fn without_pc(function: &str) -> &str {
    match function.rsplit_once("+0x") {
        Some((name, pc)) if !name.is_empty() && !pc.is_empty() && pc.bytes().all(|b| b.is_ascii_hexdigit()) => name,
        _ => function,
    }
}

/// Whether two of the `entry | record` candidates of an ambiguous record are
/// one record in different entries: more of its path cannot tell those apart.
pub fn several_entries_define(candidates: &[String]) -> bool {
    let records: Vec<&str> = candidates.iter().filter_map(|candidate| candidate.split_once(" | ")).map(|(_, record)| record).collect();
    records.iter().enumerate().any(|(i, record)| records[..i].contains(record))
}

/// A name pattern: a regex, or (`literal` / `exact`) plain text.
///
/// # Errors
/// An invalid regex.
pub fn pattern(text: &str, literal: bool, exact: bool) -> Result<Pattern, EngineError> {
    match (literal, exact) {
        (_, true) => Ok(Pattern::exact(text)),
        (true, false) => Ok(Pattern::contains(text)),
        (false, false) => Pattern::regex(text),
    }
}

/// As [`pattern`], for the name of a property, a global or a function:
/// `=NAME` is the exact name too, as a condition writes it.
///
/// # Errors
/// An invalid regex.
fn name_pattern(text: &str, literal: bool, exact: bool) -> Result<Pattern, EngineError> {
    match text.strip_prefix('=') {
        Some(name) if !literal && !exact => Ok(Pattern::exact(name)),
        _ => pattern(text, literal, exact),
    }
}

/// The roots `to` names: the callee paths a lone `call:PATTERN` matches,
/// else the functions the rule matches.
pub fn rule_roots(rule: Query) -> CallRoots {
    match rule {
        Query::Call(pattern) => CallRoots::Leaf(pattern),
        other => CallRoots::Matching(other),
    }
}

/// The root a function spelling names: `function` in `record`, or one text
/// as result rows print it (`RECORD->FUNCTION`, `RECORD->FUNCTION+0xPC`), or
/// a function name alone (every function of that name).
pub fn function_roots(record: Option<&str>, function: &str, entry: Option<&str>) -> CallRoots {
    let (record, function) = match (record, function.split_once("->")) {
        (None, Some((record, function))) => (Some(record), function),
        _ => (record, function),
    };
    CallRoots::Function { record: record.map(str::to_owned), function: without_pc(function).to_owned(), entry: entry.map(str::to_owned) }
}

/// The hint of a walk whose `to` pattern matched no callee path (`search`:
/// how the front end spells the search that lists them).
pub fn no_leaf_hint(rule: &str, search: &str) -> String {
    format!(
        "no call site has a callee path matching {rule}: the paths are what {search} prints \
         (import:REQUEST#NAME.member, global:NAME.member, this.member); `{search} .` lists them all"
    )
}

/// The hint of a callers walk from functions that found no caller, or
/// `None` (`search`: how the front end spells a search for call sites by
/// member name).
pub fn no_callers_hint(tree: &CallTree, search: &str) -> Option<String> {
    let only_roots = !tree.rows.is_empty() && tree.rows.iter().all(|row| row.depth == 0 && matches!(row.node, CallNode::Function { .. }));
    (tree.direction == Direction::Callers && tree.depth > 0 && only_roots).then(|| {
        format!(
            "no caller was resolved: a function the system calls (a lifecycle or event callback) or one reached only through a \
             value (a property, an argument) has none; {search} lists call sites by member name"
        )
    })
}

/// What a class of a HarmonyOS program is named by, for the error of a name
/// that finds none (`search`: how the front end spells the search that
/// lists the functions of a name, constructors included).
pub fn no_class_hint(search: &str) -> String {
    format!(
        "a class is named as rows print it, RECORD->CLASS, or by its name alone; a parent outside the program by import:REGEX or \
         global:REGEX over its path; {search} lists the functions of a name, constructors among them"
    )
}

/// `entries: a, b, ... (N more)`: the ABC entries of the program, for the
/// error of an `entry` that names none of them.
pub fn entries_hint(engine: &Engine) -> String {
    let names: Vec<&str> = engine.entries().map(|entry| entry.name.as_str()).collect();
    let mut hint = format!("entries: {}", names.iter().take(MAX_ENTRIES_LISTED).copied().collect::<Vec<_>>().join(", "));
    if names.len() > MAX_ENTRIES_LISTED {
        hint.push_str(&format!(", ... {} more", names.len() - MAX_ENTRIES_LISTED));
    }
    hint.push_str("; a package names all of its entries");
    hint
}

/// A tree as both front ends print it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TreeText {
    /// One line per row.
    pub lines: Vec<String>,
    /// `#` lines after the rows: what the walk covered, what was left out.
    pub footer: String,
}

impl TreeText {
    /// The rows of `tree`. Rows name their ABC entry only when the
    /// functions of the tree come from several; `several_entries`: the
    /// program has more than one, and the footer then names the one entry
    /// of a tree that has one.
    pub fn of(tree: &CallTree, several_entries: bool) -> TreeText {
        let mut entries = tree.rows.iter().filter_map(|row| match &row.node {
            CallNode::Function { entry, .. } => Some(entry.as_str()),
            CallNode::Leaf { .. } => None,
        });
        let first = entries.next();
        let with_entry = entries.any(|entry| Some(entry) != first);
        let lines = tree.lines(with_entry);
        let mut footer = tree.footer();
        if let (Some(entry), true, false) = (first, several_entries, with_entry) {
            let at = footer.find('\n').unwrap_or(footer.len());
            footer.insert_str(at, &format!("; all in {entry}"));
        }
        TreeText { lines, footer }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_ark_engine::{CallRow, EdgeKind, LeafKind};

    fn function(entry: &str, name: &str) -> CallNode {
        CallNode::Function { entry: entry.into(), record: "&a/b&".into(), function: format!("#~@0>#{name}"), restored: format!("B.{name}") }
    }

    fn row(depth: usize, parent: Option<usize>, node: CallNode) -> CallRow {
        CallRow::new(depth, parent, node, parent.map(|_| EdgeKind::Call))
    }

    fn tree(rows: Vec<CallRow>) -> CallTree {
        let mut tree = CallTree::new(Direction::Callers, 3, rows);
        tree.records_scanned = 1;
        tree
    }

    #[test]
    fn functions_lose_the_pc_of_a_row() {
        assert_eq!(without_pc("#~@0>#build+0x12"), "#~@0>#build");
        assert_eq!(without_pc("#~@0>#build"), "#~@0>#build");
        assert_eq!(without_pc("a+0xzz"), "a+0xzz");
        assert!(several_entries_define(&["a.abc | &x&".into(), "b.abc | &x&".into()]));
        assert!(!several_entries_define(&["a.abc | &x&".into(), "a.abc | &y&".into()]));
    }

    #[test]
    fn targets_come_apart_at_the_arrow() {
        let t = ClassTarget::parse("&a/b&->#~@0>#build+0x12", None);
        assert_eq!((t.record(), t.function()), ("&a/b&", Some("#~@0>#build+0x12")));
        let t = ClassTarget::parse("pages/Index", Some("Index.build"));
        assert_eq!((t.record(), t.function()), ("pages/Index", Some("Index.build")));
        assert_eq!(ClassTarget::parse("pages/Index", None).function(), None);
    }

    #[test]
    fn function_lists_stay_short() {
        let source = ".record r\n.function #~@0>#build  ; Index.build\n; x\n  0000  lda v0\n\n.function func_main_0\n";
        assert_eq!(function_list(source), "#~@0>#build (Index.build), func_main_0");
        let many: String = (0..400).map(|i| format!(".function f{i:0>20}\n")).collect();
        let listed = function_list(&many);
        assert!(listed.len() <= MAX_FUNCTIONS_LISTED + 32 && listed.ends_with(" more"), "{listed}");
    }

    #[test]
    fn search_kinds_read_their_flags() {
        let query = |kind: &str, args: SearchArgs<'_>| SearchKind::named(kind).unwrap().query(&args).unwrap();
        assert!(matches!(query("string", SearchArgs::new("a.b").literal(true)), Query::StringLiteral(_)));
        assert!(matches!(query("call", SearchArgs::new("{string:token}")), Query::CallTo(_)));
        assert!(matches!(query("call", SearchArgs::new("x(").literal(true)), Query::Call(_)));
        let Query::Prop { access, .. } = query("prop", SearchArgs::new("=x").access(Some(Access::Write))) else { panic!() };
        assert_eq!(access, Some(Access::Write));
        let Query::Import { declarations_only, .. } = query("import", SearchArgs::new("@ohos:net.http").declarations_only(true)) else {
            panic!()
        };
        assert!(declarations_only);
        assert!(SearchKind::named("call").unwrap().query(&SearchArgs::new("x(")).is_err());
        assert!(SearchKind::named("type").is_none());
    }

    #[test]
    fn names_are_regexes_unless_exact() {
        let matches = |pattern: Result<Pattern, EngineError>, text: &str| pattern.unwrap().is_match(text);
        assert!(matches(name_pattern("=load", false, false), "load") && !matches(name_pattern("=load", false, false), "reload"));
        assert!(matches(name_pattern("^re", false, false), "reload"));
        assert!(matches(name_pattern("a.b", true, false), "xa.by") && !matches(name_pattern("a.b", true, false), "axb"));
        assert!(matches(pattern("=x", false, true), "=x"));
        assert!(pattern("(", false, false).is_err());
    }

    #[test]
    fn roots_come_from_every_spelling() {
        let root = |record, function| match function_roots(record, function, Some("ets/modules.abc")) {
            CallRoots::Function { record, function, entry } => (record, function, entry),
            other => panic!("{other:?}"),
        };
        let entry = Some("ets/modules.abc".to_owned());
        assert_eq!(root(None, "&a/b&->#~@0>#build+0x1f"), (Some("&a/b&".to_owned()), "#~@0>#build".to_owned(), entry.clone()));
        assert_eq!(root(Some("pages/Index"), "Index.build"), (Some("pages/Index".to_owned()), "Index.build".to_owned(), entry.clone()));
        assert_eq!(root(None, "Index.build"), (None, "Index.build".to_owned(), entry));
        let roots = |rule: &str| rule_roots(Query::rule(rule, None).unwrap());
        assert!(matches!(roots("call:^import:@ohos:net\\.http"), CallRoots::Leaf(_)));
        assert!(matches!(roots("string:token"), CallRoots::Matching(Query::StringRegex(_))));
        assert!(matches!(roots("call:x & string:token"), CallRoots::Matching(Query::All(_))));
        assert!(matches!(roots("call:{string:token}"), CallRoots::Matching(Query::CallTo(_))));
    }

    #[test]
    fn a_tree_of_one_entry_names_it_once() {
        let one = tree(vec![row(0, None, function("a.abc", "x")), row(1, Some(0), function("a.abc", "y"))]);
        let text = TreeText::of(&one, true);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#x | B.x", "  1 <- &a/b&->#~@0>#y | B.y"]);
        assert_eq!(text.footer, "# 2 rows, 2 distinct functions, 0 leaves (callers, depth 3); 1 records scanned; all in a.abc");
        assert!(!TreeText::of(&one, false).footer.contains("all in"));
        let two = tree(vec![row(0, None, function("a.abc", "x")), row(1, Some(0), function("b.abc", "y"))]);
        let text = TreeText::of(&two, true);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#x | B.x [a.abc]", "  1 <- &a/b&->#~@0>#y | B.y [b.abc]"]);
        assert!(!text.footer.contains("all in"), "{}", text.footer);
    }

    #[test]
    fn from_rows_and_what_was_left_out_are_said() {
        let mut walked = tree(vec![row(0, None, function("a.abc", "send")), row(1, Some(0), function("a.abc", "onCreate"))]);
        walked.rows[1].from = true;
        walked.pruned = 2;
        walked.reached = Some(asc_ark_engine::Reached::new(1, 6));
        let text = TreeText::of(&walked, true);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#send | B.send", "  1 <- &a/b&->#~@0>#onCreate | B.onCreate [from]"]);
        assert_eq!(
            text.footer,
            "# 2 rows, 2 distinct functions, 0 leaves (callers, depth 3); 1 records scanned; 1 from functions reached; \
             2 functions left out by unless; all in a.abc"
        );
        let mut nowhere = tree(Vec::new());
        nowhere.reached = Some(asc_ark_engine::Reached::new(0, 6));
        let footer = TreeText::of(&nowhere, false).footer;
        assert!(
            footer.contains("; 0 from functions reached\n# from: none of the 6 callers walked matches (depth 3); a path ends"),
            "{footer}"
        );
    }

    #[test]
    fn leaves_and_skipped_subclasses_are_said() {
        let leaf = |path: &str, kind| row(1, Some(0), CallNode::Leaf { path: path.into(), kind });
        let mut walked = tree(vec![
            row(0, None, function("a.abc", "send")),
            leaf("import:@ohos:net.http#default.createHttp", LeafKind::External),
            leaf("import:lib#Store.open().read", LeafKind::Unlinked),
            leaf("arg0.then", LeafKind::Unresolved),
        ]);
        walked.rows[0].subclasses_skipped = 3;
        let text = TreeText::of(&walked, true);
        assert_eq!(
            text.lines,
            [
                "0 &a/b&->#~@0>#send | B.send [3+ subclasses skipped]",
                "  1 <- import:@ohos:net.http#default.createHttp [external]",
                "  1 <- import:lib#Store.open().read [unlinked]",
                "  1 <- arg0.then [unresolved]",
            ]
        );
        // The entry goes on the first line of the footer, what was skipped on its own.
        let (first, skipped) = text.footer.split_once('\n').unwrap();
        assert!(first.ends_with("; all in a.abc") && skipped.starts_with("# subclasses skipped: 1 rows are methods"), "{}", text.footer);
    }
}
