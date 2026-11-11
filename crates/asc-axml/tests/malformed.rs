//! Malformed binary XML returns an error or a partial document, never a
//! panic: deterministic mutants and every truncation of the fixtures.

use asc_axml::{Element, Resolver};
use asc_fixture::mutate::mutants;
use asc_fixture::res::{audit_manifest, audit_res_files};

struct Names;

impl Resolver for Names {
    fn reference(&self, id: u32) -> Option<String> {
        Some(format!("type/r{id:x}"))
    }

    fn attr_name(&self, id: u32) -> Option<String> {
        (id & 1 == 0).then(|| format!("attr{id:x}"))
    }
}

fn exercise(data: &[u8]) {
    let _ = asc_axml::decode(data);
    let _ = asc_axml::decode_with(data, Some(&Names));
    if let Ok(root) = asc_axml::parse_tree(data, Some(&Names)) {
        let mut stack: Vec<&Element> = vec![&root];
        while let Some(element) = stack.pop() {
            for attr in &element.attrs {
                let _ = (attr.as_bool(), attr.as_int(), attr.reference());
            }
            stack.extend(&element.children);
        }
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![audit_manifest(30).0];
    seeds.extend(audit_res_files().into_iter().map(|(_, bytes)| bytes));
    seeds
}

#[test]
fn mutated_documents_never_panic() {
    for (i, seed) in seeds().iter().enumerate() {
        exercise(seed);
        for mutant in mutants(seed, 0xa3 + i as u64, 1000) {
            exercise(&mutant);
        }
    }
}

#[test]
fn every_truncation_never_panics() {
    let manifest = audit_manifest(30).0;
    for len in 0..manifest.len() {
        exercise(&manifest[..len]);
    }
}
