//! `asc-findrefs`: the locators, the code scan, the instruction locator,
//! the call graph and the call-site value analysis, through a fixed set of
//! queries of every kind.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use asc_dex::Dex;
use asc_findrefs::{
    CallConstraint, Certainty, ClassQuery, CompiledQuery, FieldAccess, FindRefs, MemberQuery, Query, RefKind, ResultWant, Slot, Want,
};
use asc_findrefs::{Defined, MemberSignature, TypeMatch};

fn member(class: Option<(&str, bool)>, name: Option<&str>) -> MemberQuery {
    MemberQuery {
        class: class.map(|(pattern, precise)| ClassQuery { pattern: pattern.into(), precise }),
        name: name.map(Into::into),
        ..MemberQuery::default()
    }
}

fn queries() -> Vec<Query> {
    let method = Query::Method(member(Some(("Lexample/Test;", true)), Some("first")));
    vec![
        Query::String("t.k|^$|a".into()),
        Query::StringLiteral("token".into()),
        Query::Type("Lexample/Test;".into()),
        Query::Type("example".into()),
        method.clone(),
        Query::Method(member(None, Some("."))),
        Query::Method(MemberQuery {
            signature: Some(MemberSignature::Method { params: vec![TypeMatch::Simple { name: "String".into(), dims: 0 }], ret: None }),
            ..member(Some(("example", false)), None)
        }),
        Query::MethodSet(vec![member(Some(("Ljava/lang/Object;", true)), Some("<init>")), member(None, Some("second"))]),
        Query::Field(member(Some(("Lexample/Test;", true)), None)),
        Query::FieldAccess { field: member(None, Some(".")), access: FieldAccess::Read },
        Query::FieldAccess { field: member(None, Some(".")), access: FieldAccess::Write },
        Query::Call {
            target: Box::new(Query::Method(member(None, Some(".")))),
            constraints: vec![
                CallConstraint::Value { slot: Slot::Arg(0), want: Want::Any, certainty: Certainty::May },
                CallConstraint::Value { slot: Slot::This, want: Want::StrRegex("t".into()), certainty: Certainty::Must },
                CallConstraint::Value { slot: Slot::Arg(1), want: Want::Ret(member(None, Some("."))), certainty: Certainty::May },
                CallConstraint::Value { slot: Slot::Arg(2), want: Want::Field(member(None, Some("."))), certainty: Certainty::May },
                CallConstraint::Value { slot: Slot::Arg(3), want: Want::Param(None), certainty: Certainty::May },
                CallConstraint::Result { want: ResultWant::Unused, certainty: Certainty::May },
            ],
        },
        Query::Extends("Ljava/lang/Object;".into()),
        Query::Implements("Ljava/lang/Runnable;".into()),
        Query::Defined(Defined::Flags(asc_dex::access::STATIC)),
        Query::Defined(Defined::Annotation("Lexample/Mark;".into())),
        Query::Defined(Defined::Members { classes: vec!["Lexample/Test;".into()], name: Some("first".into()), proto: Some("()V".into()) }),
        Query::All { all: vec![Query::String("token".into()), method], none: vec![Query::Type("LMissing;".into())] },
    ]
}

fn compiled() -> &'static [CompiledQuery] {
    static COMPILED: OnceLock<Vec<CompiledQuery>> = OnceLock::new();
    COMPILED.get_or_init(|| queries().iter().map(|q| CompiledQuery::new(q).expect("fixed query compiles")).collect())
}

pub fn run(data: &[u8]) {
    let Ok(dex) = Dex::parse(data) else { return };
    let refs = FindRefs::new(&dex);
    let queries = compiled();
    for query in queries {
        let _ = refs.cannot_match(query);
        let _ = refs.locate_compiled(query);
        let _ = refs.find_ref_compiled(query);
        let _ = refs.class_relation(query);
    }
    let _ = refs.find_many(&queries.iter().collect::<Vec<_>>());
    let idxs: BTreeSet<u32> = [0, 1, 2, 5, 0xffff].into();
    for kind in [RefKind::String, RefKind::Type, RefKind::Method, RefKind::Field] {
        let _ = refs.scan_idxs(kind, &idxs);
    }
    if let Ok(graph) = refs.call_graph() {
        for method in 0..dex.method_count().min(crate::MAX_ITEMS) {
            let _ = (graph.callees(method), graph.callers(method), graph.has_body(method));
        }
        let _ = asc_findrefs::CallGraph::from_bytes(&graph.to_bytes());
    }
}
