//! Captured-variable resolution and the call graph on the real samples
//! (skipped when they are not there). The numbers the engine reports were
//! checked against the official `ark_disasm` listing of a large sample by
//! independent re-derivations: environments and writers of every resolved
//! captured callee, the export and definition behind every edge through an
//! import, and the callee path of 30,000 call sites.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{
    CallEdge, CallNode, CallQuery, CallRoots, CalleeRoot, ClassQuery, Direction, EdgeKind, Engine, GraphSize, Pattern, RequestForm,
    ResolutionOptions, Unresolved,
};
use common::{large_sample_dir, sample};

fn edges(engine: &Engine) -> (Vec<CallEdge>, GraphSize) {
    let mut out = Vec::new();
    let size = engine.call_edges(&AtomicBool::new(false), &mut |edge| out.push(edge)).unwrap();
    (out, size)
}

/// Edges per kind and what they lead to: `function`, `import` (a function
/// through an import), `external`, `unlinked`, `unresolved`.
fn census(edges: &[CallEdge]) -> BTreeMap<(EdgeKind, &'static str), usize> {
    let mut out = BTreeMap::new();
    for edge in edges {
        let to = match (&edge.to, &edge.via) {
            (CallNode::Function { .. }, Some(_)) => "import",
            (CallNode::Function { .. }, None) => "function",
            (CallNode::Leaf { kind, .. }, _) => kind.label(),
        };
        *out.entry((edge.kind, to)).or_default() += 1;
    }
    out
}

fn level_one(engine: &Engine, node: &CallNode, direction: Direction) -> HashSet<CallNode> {
    let CallNode::Function { entry, record, function, .. } = node else { return HashSet::new() };
    let roots = CallRoots::Function { record: Some(record.clone()), function: function.clone(), entry: Some(entry.clone()) };
    let query = CallQuery { depth: 1, max_nodes: usize::MAX, ..CallQuery::new(roots, direction) };
    let tree = engine.call_graph(&query, &AtomicBool::new(false)).unwrap();
    tree.rows.into_iter().filter(|row| row.depth == 1).map(|row| row.node).collect()
}

/// Every `step`-th edge between functions is seen from both ends; the
/// callers side on an engine that has loaded nothing else. A smoke test:
/// `examples/arkcg.rs check` does this for every function.
fn both_directions_agree(open: &dyn Fn() -> Engine, full: &Engine, all: &[CallEdge], step: usize) {
    for edge in all.iter().filter(|edge| matches!(edge.to, CallNode::Function { .. })).step_by(step) {
        assert!(level_one(&open(), &edge.to, Direction::Callers).contains(&edge.from), "{edge:?}");
        assert!(level_one(full, &edge.from, Direction::Callees).contains(&edge.to), "{edge:?}");
    }
}

#[test]
fn contacts_captured_variables_and_graph() {
    let Some(path) = sample("contacts.hap") else { return };
    let engine = Engine::open(&path).unwrap();
    let cancel = AtomicBool::new(false);
    // The application's own code: every captured callee resolves.
    let own = engine.call_resolution(&ResolutionOptions { records: Some("&entry/"), samples: true }, &cancel).unwrap();
    assert_eq!((own.call_sites, own.captured, own.captured_resolved), (318, 63, 63));
    assert_eq!((own.before.get(&CalleeRoot::Lexical), own.after.get(&CalleeRoot::Lexical)), (Some(&59), None));
    // This build names its environment slots (`newlexenvwithname`), which says what a slot holds
    // without any analysis: every callee resolved to `this…` reads a slot the compiler calls
    // `this`, in an environment of the function that stores it.
    let through_this: Vec<_> = own.samples.iter().filter(|sample| sample.callee.starts_with("this")).collect();
    assert_eq!(through_this.len(), 40);
    for sample in through_this {
        let query = ClassQuery { record: &sample.record, function: Some(&sample.writer), entry: None };
        let writer = engine.get_class(&query).unwrap().text;
        let (last, inner) = (format!("\"this\", {} ]", sample.slot), format!("\"this\", {},", sample.slot));
        let named = writer.lines().any(|line| line.contains("newlexenvwithname") && (line.contains(&last) || line.contains(&inner)));
        assert!(named, "{sample:?}\n{writer}");
    }
    // The whole file: a bundled library keeps most of its state in variables written more than once.
    let all = engine.call_resolution(&ResolutionOptions::default(), &cancel).unwrap();
    assert_eq!((all.call_sites, all.captured, all.captured_resolved), (21_116, 8_218, 5_668));
    let why = |reason| all.captured_unresolved.get(&reason).copied().unwrap_or(0);
    assert_eq!((why(Unresolved::MultipleWriters), why(Unresolved::UnknownValue), why(Unresolved::NoIdentity)), (2_450, 100, 0));
    assert_eq!((all.scopes.unidentified_functions, all.scopes.undefined_functions, all.scopes.foreign_definitions), (0, 0, 0));

    let (graph, size) = edges(&engine);
    let census = census(&graph);
    let count = |kind, to| census.get(&(kind, to)).copied().unwrap_or(0);
    assert_eq!((graph.len(), size.records, size.functions, size.edges), (26_918, 25, 5_894, 26_918));
    assert_eq!((count(EdgeKind::Call, "function"), count(EdgeKind::Call, "import"), count(EdgeKind::New, "import")), (3_573, 2, 4));
    assert_eq!(
        (count(EdgeKind::Call, "external"), count(EdgeKind::Call, "unresolved"), count(EdgeKind::Defines, "function")),
        (3_937, 11_887, 5_802)
    );
    // Calls on what a function of the program returned: the import is of the program, the callee is not told.
    assert_eq!((count(EdgeKind::Call, "unlinked"), count(EdgeKind::ThisClass, "function")), (3, 8));
    // Who reaches the HTTP client: the two helpers, and the page code that calls them.
    let http =
        CallQuery { depth: 2, ..CallQuery::new(CallRoots::Leaf(Pattern::regex("^import:@ohos:net\\.http").unwrap()), Direction::Callers) };
    let tree = engine.call_graph(&http, &cancel).unwrap();
    let lines = tree.lines(false);
    assert_eq!(lines.len(), 12, "{lines:?}");
    assert_eq!(lines[0], "0 import:@ohos:net.http#default.createHttp().request [external]");
    assert_eq!(lines[3], "  1 <- &entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo | utils.o0O0OOoo");
    assert_eq!(lines[4], "    2 <- &entry/src/main/ets/components/UserList&->#~@0>@1*#^3 | UserList.UserItem.<anonymous>^3");
    assert_eq!(tree.footer(), "# 12 rows, 5 distinct functions, 3 leaves (callers, depth 2); 25 records scanned");

    both_directions_agree(&|| Engine::open(&path).unwrap(), &engine, &graph, 2_003);
    let forms = engine.request_forms(&cancel).unwrap();
    assert_eq!(forms.get(&RequestForm::Normalized).map(|count| (count.requests, count.resolved)), Some((17, 17)));
}

/// On a 32 MB store sample (4,840 records, 93,930 functions): 284,565 call
/// sites, 49,094 of 53,548 captured callees resolved, 346,983 edges, 50,594
/// of them through an import to a function of the program. What is asserted
/// here is what makes such numbers add up, for any program.
#[test]
fn large_sample_captured_variables_and_graph() {
    let Some(dir) = large_sample_dir() else { return };
    let path = dir.join("modules.abc");
    let engine = Engine::open(&path).unwrap();
    let cancel = AtomicBool::new(false);
    let stats = engine.call_resolution(&ResolutionOptions::default(), &cancel).unwrap();
    assert!(0 < stats.scoped_records && stats.scoped_records <= stats.records && stats.records < stats.call_sites);
    // A captured callee is resolved or has one reason why not; most are resolved.
    let unresolved: usize = stats.captured_unresolved.values().sum();
    assert_eq!(stats.captured, stats.captured_resolved + unresolved);
    assert!(stats.captured_resolved > unresolved * 4, "{} of {}", stats.captured_resolved, stats.captured);
    let why = |reason| stats.captured_unresolved.get(&reason).copied().unwrap_or(0);
    // No function of this file is given up, and none is created outside its record.
    assert_eq!((why(Unresolved::NoIdentity), why(Unresolved::Tainted), why(Unresolved::Outside), why(Unresolved::Chain)), (0, 0, 0, 0));
    assert_eq!((stats.scopes.unidentified_functions, stats.scopes.undefined_functions, stats.scopes.foreign_definitions), (0, 0, 0));
    assert_eq!(stats.scopes.odd_class_literals, 0);
    // Resolution moves call sites between roots, it makes none: the captured variables that
    // resolve leave their root, no other root loses.
    let root = |root| (stats.before.get(&root).copied().unwrap_or(0), stats.after.get(&root).copied().unwrap_or(0));
    assert_eq!(stats.before.values().sum::<usize>(), stats.call_sites);
    assert_eq!(stats.after.values().sum::<usize>(), stats.call_sites);
    let (before, after) = root(CalleeRoot::Lexical);
    assert!(after < before && before - after <= stats.captured_resolved, "{before} -> {after}");
    for other in CalleeRoot::ALL.into_iter().filter(|root| *root != CalleeRoot::Lexical) {
        let (before, after) = root(other);
        assert!(before <= after, "{other:?}: {before} -> {after}");
    }
    assert_eq!(root(CalleeRoot::CapturedThis).0, 0);

    let (graph, size) = edges(&engine);
    assert_eq!((size.records, size.edges), (stats.records, graph.len()));
    let census = census(&graph);
    assert_eq!(census.values().sum::<usize>(), graph.len());
    let count = |kind, to| census.get(&(kind, to)).copied().unwrap_or(0);
    // Call sites lead through an import to a function of the program, and to one of their record.
    assert!(count(EdgeKind::Call, "import") > 0 && count(EdgeKind::New, "import") > 0, "{census:?}");
    assert!(count(EdgeKind::Call, "function") > 0 && count(EdgeKind::ThisClass, "function") > 0, "{census:?}");
    // A definition names a function of the program, nothing else.
    assert_eq!(census.keys().filter(|(kind, _)| *kind == EdgeKind::Defines).collect::<Vec<_>>(), [&(EdgeKind::Defines, "function")]);
    assert!(count(EdgeKind::Defines, "function") < size.functions);
    // An edge through an import ends at a function that exists, in another record or its own.
    for edge in graph.iter().filter(|edge| edge.via.is_some()) {
        assert!(matches!(&edge.to, CallNode::Function { record, function, .. } if record != "?" && function != "?"), "{edge:?}");
    }
    // Every request for a record of the program resolves; native, system and plain modules
    // have nothing in the file to resolve to.
    let forms = engine.request_forms(&cancel).unwrap();
    let form = |form| forms.get(&form).map(|count| (count.requests, count.resolved));
    assert!(matches!(form(RequestForm::Normalized), Some((requests, resolved)) if requests > 0 && requests == resolved));
    for outside in [RequestForm::NormalizedNative, RequestForm::System, RequestForm::Plain] {
        assert!(form(outside).is_none_or(|(_, resolved)| resolved == 0), "{outside:?}: {:?}", form(outside));
    }

    // The function with the most callers, asked of an engine that has loaded nothing else: the
    // rows are its callers in the whole graph, and only the records that can name it are read.
    let mut callers: HashMap<&CallNode, HashSet<&CallNode>> = HashMap::new();
    for edge in graph.iter().filter(|edge| matches!(edge.to, CallNode::Function { .. }) && edge.kind != EdgeKind::Defines) {
        callers.entry(&edge.to).or_default().insert(&edge.from);
    }
    let (popular, from) = callers.iter().max_by_key(|(_, from)| from.len()).unwrap();
    let found = level_one(&Engine::open(&path).unwrap(), popular, Direction::Callers);
    assert_eq!(found.iter().collect::<HashSet<_>>(), *from);
    let CallNode::Function { entry, record, function, .. } = popular else { unreachable!() };
    let roots = CallRoots::Function { record: Some(record.clone()), function: function.clone(), entry: Some(entry.clone()) };
    let query = CallQuery { depth: 1, max_nodes: usize::MAX, ..CallQuery::new(roots, Direction::Callers) };
    let tree = Engine::open(&path).unwrap().call_graph(&query, &cancel).unwrap();
    assert!(!tree.truncated && tree.records_scanned < size.records, "{} of {}", tree.records_scanned, size.records);
    both_directions_agree(&|| Engine::open(&path).unwrap(), &engine, &graph, 20_011);
}

/// The edges that go through the class hierarchy, exported objects and
/// decorated classes, and the requests the documents of a package resolve,
/// on the large sample opened as its directory (the package and its
/// decrypted code). What is asserted holds for any program.
#[test]
fn large_sample_class_edges_and_package_requests() {
    let Some(dir) = large_sample_dir() else { return };
    let cancel = AtomicBool::new(false);
    let engine = Engine::open(&dir).unwrap();
    let (graph, size) = edges(&engine);
    let census = census(&graph);
    let count = |kind, to| census.get(&(kind, to)).copied().unwrap_or(0);
    // These kinds are edges to functions: a call site they do not resolve stays a plain leaf.
    let class_kinds = [EdgeKind::Super, EdgeKind::Instance, EdgeKind::ThisClass, EdgeKind::Inherited, EdgeKind::Reassigned];
    for kind in class_kinds {
        assert_eq!((count(kind, "external"), count(kind, "unlinked"), count(kind, "unresolved")), (0, 0, 0), "{kind:?}");
        assert!(count(kind, "function") + count(kind, "import") > 0, "{kind:?}: {census:?}");
    }
    for edge in graph.iter().filter(|edge| class_kinds.contains(&edge.kind)) {
        let (CallNode::Function { record: from, .. }, CallNode::Function { function, record, .. }) = (&edge.from, &edge.to) else {
            panic!("{edge:?}")
        };
        assert!(record != "?" && function != "?", "{edge:?}");
        match edge.kind {
            // An inherited method is not the caller's own, and `super` never leads back to the caller.
            EdgeKind::Inherited | EdgeKind::Super => assert_ne!(edge.from, edge.to, "{edge:?}"),
            // The class of the calling method is in the caller's record.
            EdgeKind::ThisClass => assert_eq!(from, record, "{edge:?}"),
            _ => {}
        }
    }
    // The package says where its requests lead; the bare code file alone does not. Nothing that
    // resolved without the documents is lost with them.
    // (The package may hold more code files than the one that was decrypted.)
    let bare = Engine::open(dir.join("modules.abc")).unwrap();
    let bare_size = bare.build_call_graph(&cancel).unwrap();
    assert!(bare_size.functions <= size.functions && bare_size.edges <= size.edges, "{bare_size:?} {size:?}");
    let (forms, bare_forms) = (engine.request_forms(&cancel).unwrap(), bare.request_forms(&cancel).unwrap());
    for (form, without) in &bare_forms {
        let count = forms.get(form).copied().unwrap_or_default();
        assert!(without.requests <= count.requests && without.resolved <= count.resolved && count.resolved <= count.requests, "{form:?}");
    }
    let to_functions = |engine: &Engine| {
        let mut functions = 0;
        engine.call_edges(&cancel, &mut |edge| functions += usize::from(matches!(edge.to, CallNode::Function { .. }))).unwrap();
        functions
    };
    assert!(to_functions(&bare) <= graph.iter().filter(|edge| matches!(edge.to, CallNode::Function { .. })).count());

    // Both ends of the edges of each kind agree, the callers side on an engine that has loaded
    // nothing: the records a callers walk picks reach through subclasses and exported objects.
    for kind in class_kinds {
        let of_kind: Vec<CallEdge> = graph.iter().filter(|edge| edge.kind == kind).cloned().collect();
        both_directions_agree(&|| Engine::open(&dir).unwrap(), &engine, &of_kind, of_kind.len() / 8 + 1);
    }
    // The memory the analyses take is accounted for, and given back.
    let held = engine.memory_use().analyses;
    assert!(held > 0 && engine.release_analyses() == held && engine.memory_use().analyses == 0);
}
