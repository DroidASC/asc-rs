//! A file the official compiler wrote, kept in the repository: the one
//! layout the fixture writer cannot produce, and small (1.5 KB).
//!
//! `tests/es2abc/annotations.api24.abc` is `tests/es2abc/annotations.ts`
//! compiled on its own, not merged, for bytecode 24.0.0.0:
//!
//! ```text
//! cd tests/es2abc
//! es2abc --target-api-version 24 --module --extension ts --enable-annotations \
//!     --output annotations.api24.abc annotations.ts
//! ```
//!
//! It has what no sample has: the newest bytecode version, the records of
//! an unmerged file (`_GLOBAL` with every function, `_ESModuleRecord` and
//! `_ESScopeNamesRecord` with a field named after the source), annotation
//! interfaces with typed default values and functions that carry them.
//! `oracle.rs` compiles the same source again and compares it with the
//! official disassembler when the tools are there.

use asc_abc::{Abc, ElementValue, MethodTag, Version, unmerged};
use asc_pasm::{Options, write_record};

const COMPILED: &[u8] = include_bytes!("es2abc/annotations.api24.abc");

fn listing(abc: &Abc<'_>, record: &[u8]) -> String {
    let class = abc.find_record(record).unwrap().unwrap().local().unwrap();
    let mut text = String::new();
    write_record(&mut text, abc, &class, &Options::default()).unwrap();
    text
}

#[test]
fn an_unmerged_file_has_its_module_record_and_scope_names() {
    let abc = Abc::parse(COMPILED).unwrap();
    assert_eq!(abc.header().version, Version([24, 0, 0, 0]));
    assert!(abc.literal_array_index().unwrap().is_none(), "no literal array index since 13.0.1.0");
    let global = abc.find_record(unmerged::GLOBAL).unwrap().unwrap().local().unwrap();
    // Neither is a field of `_GLOBAL`: each is the only field of a record of its own.
    assert_eq!(global.num_fields, 0);
    let module = global.module_record().unwrap().expect("the module record of the file");
    assert_eq!(module.local_exports.len(), 1);
    assert_eq!(global.scope_names().unwrap().expect("the scope names of the file").len(), 1);
    // Another record of the file does not take them for its own.
    let holder = abc.find_record(unmerged::MODULE_RECORD).unwrap().unwrap().local().unwrap();
    assert!(holder.module_record().unwrap().is_none() && holder.scope_names().unwrap().is_none());

    let text = listing(&abc, unmerged::GLOBAL);
    assert!(text.starts_with(".record _GLOBAL\n; module, 0 fields, 4 functions\n.module\n"), "{text}");
    assert!(text.contains("  0035  stmodulevar 0  ; export { tagged }\n"), "{text}");
    // `@0` of a function name is the class the scope names say.
    assert!(text.contains(".function #~@0<#make  ; Tagged.make\n") && !text.contains("<error"), "{text}");
}

#[test]
fn annotations_of_the_program_are_listed_with_their_values() {
    let abc = Abc::parse(COMPILED).unwrap();
    let text = listing(&abc, unmerged::GLOBAL);
    let header = |function: &str| -> Vec<&str> {
        let at = text.find(&format!(".function {function}")).unwrap();
        text[at..].lines().skip(2).take_while(|line| line.starts_with("; ")).collect()
    };
    // Without values, with some, and the one of the class, which stands on its constructor.
    assert_eq!(header("#~@0>#run"), ["; @Marked", "; @Bare"]);
    assert_eq!(header("#~@0<#make"), ["; @Marked(level=-0.5, tags=[ \"only\" ])"]);
    assert_eq!(
        header("#~@0=#Tagged"),
        ["; @Marked(level=3.0, name=\"class\", on=false, tags=[ \"x\" ], sizes=[ 0.5 ], flags=[ false ], grid=[ [ 4.0 ] ])"]
    );
    // The compiler's own annotations are on every function and on no line.
    assert!(header("func_main_0").is_empty() && !text.contains("_ESSlotNumberAnnotation"), "{text}");

    assert_eq!(
        listing(&abc, b"Marked"),
        ".record Marked\n; annotation interface, 7 fields, 0 functions\n.field f64 level = 1.0\n.field Lpanda.String; name = \"plain\"\n\
         .field u1 on = 1\n.field [Lpanda.String; tags = [ \"a\", \"b\" ]\n.field [D sizes = [ 1.0, 2.5, -3.0 ]\n\
         .field [Z flags = [ true, false ]\n.field [[D grid = [ [ 1.0, 2.0 ], [ 3.0 ] ]\n"
    );
    assert_eq!(listing(&abc, b"Bare"), ".record Bare\n; annotation interface, 0 fields, 0 functions\n");
}

#[test]
fn annotation_elements_are_read_by_their_type() {
    let abc = Abc::parse(COMPILED).unwrap();
    let global = abc.find_record(unmerged::GLOBAL).unwrap().unwrap().local().unwrap();
    let constructor = global.methods().unwrap().map(Result::unwrap).find(|method| method.name().unwrap().bytes == b"#~@0=#Tagged").unwrap();
    let mut values = Vec::new();
    for tag in constructor.tags().map(Result::unwrap) {
        let MethodTag::Annotation(off) = tag else { continue };
        let annotation = abc.annotation(off).unwrap();
        for element in annotation.elements() {
            let name = abc.string(element.name_off).unwrap().to_str().into_owned();
            let value = match element.typed(&abc).unwrap() {
                ElementValue::String(off) => format!("string {}", abc.string(off).unwrap().to_str()),
                ElementValue::Array(off) => format!("array of {}", abc.literal_array(off).unwrap().len()),
                other => format!("{other:?}"),
            };
            values.push(format!("{name}: {value}"));
        }
    }
    assert_eq!(
        values,
        [
            "level: F64(3.0)",
            "name: string class",
            "on: Bool(false)",
            "tags: array of 1",
            "sizes: array of 1",
            "flags: array of 1",
            "grid: array of 1",
            "SlotNumber: Int(0)"
        ]
    );
}
