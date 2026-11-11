//! `asc-axml`: binary XML to text and to a tree, with and without a
//! resolver for references and attribute names.

use asc_axml::{Element, Resolver};

/// Names every id, the way a table that defines them would.
struct Everything;

impl Resolver for Everything {
    fn reference(&self, id: u32) -> Option<String> {
        Some(format!("type/r{id:x}"))
    }

    fn attr_name(&self, id: u32) -> Option<String> {
        (id & 1 == 0).then(|| format!("attr{id:x}"))
    }
}

pub fn run(data: &[u8]) {
    let _ = asc_axml::decode(data);
    let _ = asc_axml::decode_with(data, Some(&Everything));
    if let Ok(root) = asc_axml::parse_tree(data, Some(&Everything)) {
        visit(&root);
    }
    let _ = asc_axml::parse_tree(data, None);
}

/// Iterative: how deep a document nests is up to the input.
fn visit(root: &Element) {
    let mut stack = vec![root];
    while let Some(element) = stack.pop() {
        visit_one(element);
        stack.extend(&element.children);
    }
}

fn visit_one(element: &Element) {
    for attr in &element.attrs {
        let _ = (attr.is_android(), attr.as_bool(), attr.as_int(), attr.reference());
        let _ = asc_axml::android_attr_name(attr.res_id.unwrap_or_default());
    }
    let _ = (element.android("name"), element.plain("package"), element.children_named("activity").count());
}
