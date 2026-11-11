//! Searching a malformed DEX returns errors or nothing, never panics:
//! deterministic mutants of the fixtures run through a query of every kind.

use asc_dex::Dex;
use asc_findrefs::{
    CallConstraint, Certainty, ClassQuery, CompiledQuery, Defined, FieldAccess, FindRefs, MemberQuery, Query, ResultWant, Slot, Want,
};
use asc_fixture::mutate::mutants;

fn member(class: Option<&str>, name: Option<&str>) -> MemberQuery {
    MemberQuery::default()
        .with_class(class.map(|pattern| if pattern.ends_with(';') { ClassQuery::exact(pattern) } else { ClassQuery::fuzzy(pattern) }))
        .with_name(name.map(Into::into))
}

fn queries() -> Vec<CompiledQuery> {
    let any_call = Query::Method(member(None, Some(".")));
    [
        Query::String("t.k".into()),
        Query::StringLiteral("token".into()),
        Query::Type("Lexample/Test;".into()),
        Query::Method(member(Some("Lexample/Test;"), Some("first"))),
        Query::Field(member(Some("example"), None)),
        Query::FieldAccess { field: member(None, Some(".")), access: FieldAccess::Write },
        Query::Call {
            target: Box::new(any_call.clone()),
            constraints: vec![
                CallConstraint::Value { slot: Slot::Arg(0), want: Want::Str("token".into()), certainty: Certainty::May },
                CallConstraint::Value { slot: Slot::This, want: Want::Param(None), certainty: Certainty::Must },
                CallConstraint::Result { want: ResultWant::Used, certainty: Certainty::May },
            ],
        },
        Query::Extends("Ljava/lang/Object;".into()),
        Query::Implements("Ljava/lang/Runnable;".into()),
        Query::Defined(Defined::Flags(asc_dex::access::STATIC)),
        Query::All { all: vec![Query::String("token".into()), any_call], none: vec![] },
    ]
    .iter()
    .map(|q| CompiledQuery::new(q).unwrap())
    .collect()
}

fn exercise(data: &[u8], queries: &[CompiledQuery]) {
    let Ok(dex) = Dex::parse(data) else { return };
    let refs = FindRefs::new(&dex);
    for query in queries {
        let _ = refs.find_ref_compiled(query);
    }
    if let Ok(graph) = refs.call_graph() {
        for method in 0..dex.method_count().min(64) {
            let _ = (graph.callers(method), graph.callees(method));
        }
    }
}

#[test]
fn mutated_fixtures_never_panic() {
    let queries = queries();
    let seeds =
        [asc_fixture::make_dex(), asc_fixture::make_field_access_dex(), asc_fixture::make_rich_dex(), asc_fixture::make_padded_dex(5, 7)];
    for (i, seed) in seeds.iter().enumerate() {
        exercise(seed, &queries);
        for mutant in mutants(seed, 0xf1d + i as u64, 600) {
            exercise(&mutant, &queries);
        }
    }
}
