//! Write the seed corpora: `cargo run --example gen_seeds [DIR]` fills
//! `DIR/<target>/` (default `corpus/`) with the synthetic fixtures of
//! `asc-fixture` and the small sample files of the repository.

use std::fs;
use std::path::{Path, PathBuf};

use asc_abc::Abc;
use asc_dex::Dex;
use asc_fixture::abc::{
    annotations_program, call_graph_program, callable_names_program, class_calls_program, class_hierarchy_program, handed_objects_program,
    late_members_program, packaged_entry_program, packaged_library_program, patched_objects_program, sample_program,
};
use asc_fixture::hap::{
    Compression, LIBRARY_MODULE_JSON, SAMPLE_MAIN_PAGES, SAMPLE_MODULE_JSON, SAMPLE_PACK_INFO, SAMPLE_ROUTER_MAP, SAMPLE_SOURCE_MAPS,
    library_program, make_debug_hap, make_library_hsp, make_routed_hap, resource_program, routed_program, sample_resources,
};
use asc_fixture::res::{Res, Val, arsc, audit_manifest, audit_res_files};
use asc_fixture::{abc::PACKAGED_ENTRY_PKG_CONTEXT, make_abc, make_apk, make_app, make_hap, make_multi_region_abc};

fn dex_seeds() -> Vec<Vec<u8>> {
    vec![
        asc_fixture::make_dex(),
        asc_fixture::make_padded_dex(6, 10),
        asc_fixture::make_static_field_dex(),
        asc_fixture::make_field_access_dex(),
        asc_fixture::make_unsorted_static_field_dex(),
        asc_fixture::make_short_static_values_dex(),
        asc_fixture::make_class_only_dex(&["LA;", "LA$1;", "LA$1$b;", "LB;"], 0, false),
        asc_fixture::make_dex041_container(),
        asc_fixture::make_rich_dex(),
        asc_fixture::make_many_members_dex(6, true),
        asc_fixture::make_many_members_dex(6, false),
        asc_fixture::make_truncated_insn_dex(),
    ]
}

/// The code of every method of the DEX seeds, in the layout of the
/// `dalvik` target: registers, ins, no try triples, then the code.
fn dalvik_seeds(dexes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for data in dexes {
        let Ok(dex) = Dex::parse(data) else { continue };
        for class in dex.class_defs().flatten() {
            let Ok(class_data) = dex.class_data(class.class_data_off) else { continue };
            for method in class_data.methods().filter(|m| m.code_off != 0) {
                let Ok(code) = dex.code_item(method.code_off) else { continue };
                let registers = u8::try_from(code.registers_size).unwrap_or(u8::MAX);
                let ins = u8::try_from(code.ins_size).unwrap_or(u8::MAX);
                seeds.push([&[registers, ins, 0][..], code.insns].concat());
            }
        }
    }
    seeds
}

fn abc_seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![make_abc(), make_multi_region_abc()];
    let programs = [
        sample_program(),
        annotations_program(),
        callable_names_program(),
        call_graph_program(),
        class_hierarchy_program(),
        class_calls_program(),
        handed_objects_program(),
        late_members_program(),
        patched_objects_program(),
        packaged_entry_program(),
        packaged_library_program(),
        resource_program(),
        routed_program(),
        library_program(),
    ];
    seeds.extend(programs.iter().map(|p| p.build().bytes));
    seeds.extend(fs::read(repo().join("crates/harmony/asc-pasm/tests/es2abc/annotations.api24.abc")));
    seeds
}

/// The code of every method of the ABC seeds.
fn arkisa_seeds(abcs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for data in abcs {
        let Ok(abc) = Abc::parse(data) else { continue };
        let Ok(classes) = abc.classes() else { continue };
        for entry in classes.flatten() {
            let asc_abc::ClassEntry::Local(class) = entry else { continue };
            let Ok(methods) = class.methods() else { continue };
            for method in methods.flatten() {
                if let Ok(Some(code)) = method.code() {
                    seeds.push(code.instructions().to_vec());
                }
            }
        }
    }
    seeds
}

fn axml_seeds() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (manifest, table) = audit_manifest(30);
    let (old_manifest, old_table) = audit_manifest(23);
    let mut axml = vec![manifest, old_manifest];
    axml.extend(audit_res_files().into_iter().map(|(_, bytes)| bytes));
    let small = arsc(
        "com.example",
        &[
            Res::new("string", "app_name", Val::Str("Demo")).v(31, Val::Str("Demo 31")),
            Res::new("bool", "flag", Val::Bool(true)),
            Res::new("integer", "count", Val::Int(-7)),
            Res::new("style", "alias", Val::Ref(0x7f01_0000)),
        ],
    );
    (axml, vec![table, old_table, small])
}

fn json_seeds() -> Vec<Vec<u8>> {
    [
        SAMPLE_MODULE_JSON,
        LIBRARY_MODULE_JSON,
        SAMPLE_PACK_INFO,
        SAMPLE_MAIN_PAGES,
        SAMPLE_ROUTER_MAP,
        SAMPLE_SOURCE_MAPS,
        PACKAGED_ENTRY_PKG_CONTEXT,
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("fuzz/ is inside the repository").to_path_buf()
}

fn write(dir: &Path, target: &str, seeds: &[Vec<u8>]) {
    let dir = dir.join(target);
    fs::create_dir_all(&dir).expect("corpus directory is created");
    for (i, seed) in seeds.iter().enumerate() {
        fs::write(dir.join(format!("seed-{i:03}")), seed).expect("seed is written");
    }
    println!("{target}: {} seeds", seeds.len());
}

fn main() {
    let dir = std::env::args_os().nth(1).map_or_else(|| repo().join("fuzz/corpus"), PathBuf::from);
    let dexes = dex_seeds();
    let abcs = abc_seeds();
    let (axml, tables) = axml_seeds();
    let abc = make_abc();
    let apks = vec![
        make_apk(&[("classes.dex", &dexes[0]), ("AndroidManifest.xml", &axml[0]), ("resources.arsc", &tables[0])], true),
        make_apk(&[("classes.dex", &dexes[8]), ("classes2.dex", &dexes[2])], false),
        make_hap(&abc),
        make_debug_hap(&abc),
        make_routed_hap(),
        make_library_hsp(),
        make_app(&[("entry.hap", &make_hap(&abc))], Compression::Stored),
        make_app(&[("entry.hap", &make_hap(&abc))], Compression::Deflated),
        dexes[0].clone(),
    ];
    write(&dir, "dex", &dexes);
    write(&dir, "findrefs", &dexes);
    write(&dir, "rebuild", &dexes);
    write(&dir, "dalvik", &dalvik_seeds(&dexes));
    write(&dir, "abc", &abcs);
    write(&dir, "pasm", &abcs);
    write(&dir, "arkisa", &arkisa_seeds(&abcs));
    write(&dir, "axml", &axml);
    write(&dir, "arsc", &tables);
    write(&dir, "apk", &apks);
    write(&dir, "hap_json", &json_seeds());
    write(&dir, "hap_resources", &[sample_resources().build()]);
}
