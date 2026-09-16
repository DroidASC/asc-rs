//! Stage-by-stage timing of a reference search over one DEX file.
//!
//! `cargo run --release -p asc-findrefs --example profile -- classes.dex field INSTANCE`

use asc_dex::Dex;
use asc_findrefs::{CodeScanner, CompiledQuery, FindRefs, IdxSet, MemberQuery, Query, RefKind};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: profile <dex> <string|type|method|field> <pattern>");
        std::process::exit(2);
    }
    let data = std::fs::read(&args[1]).expect("read dex");
    let query = match args[2].as_str() {
        "string" => Query::String(args[3].clone()),
        "type" => Query::Type(args[3].clone()),
        "method" => Query::Method(MemberQuery { class: None, name: Some(args[3].clone()) }),
        _ => Query::Field(MemberQuery { class: None, name: Some(args[3].clone()) }),
    };
    let t = Instant::now();
    let compiled = CompiledQuery::new(&query).expect("compile query");
    println!("compile query: {:?}", t.elapsed());
    for round in 0..3 {
        let dex = Dex::parse(&data).expect("parse");
        let buf = dex.buf();
        let fr = FindRefs::new(&dex);
        let t = Instant::now();
        fr.string_locator().unwrap();
        let t_str = t.elapsed();
        let t = Instant::now();
        match compiled.kind() {
            RefKind::Method => {
                fr.method_locator().unwrap();
            }
            RefKind::Field => {
                fr.field_locator().unwrap();
            }
            RefKind::Type => {
                fr.type_locator().unwrap();
            }
            RefKind::String => {}
        }
        let t_member = t.elapsed();
        let t = Instant::now();
        let idxs = fr.locate_compiled(&compiled).unwrap();
        let t_locate = t.elapsed();
        let t = Instant::now();
        let insn = fr.insn_locator().unwrap();
        let t_insn = t.elapsed();
        let t = Instant::now();
        let set: IdxSet = idxs.iter().copied().collect();
        let matches = CodeScanner::new(insn).scan(buf, compiled.kind(), &set);
        let t_scan = t.elapsed();
        let t = Instant::now();
        let offsets: Vec<u32> = matches.iter().map(|m| m.0).collect();
        let methods = insn.locate(buf, &offsets);
        let t_resolve = t.elapsed();
        let hits = methods.iter().filter(|m| m.is_some()).count();
        println!(
            "round {round}: strings={:?} member={:?} locate={:?} ({} idx) insn_table={:?} scan={:?} ({} cand, region {} KiB) resolve={:?} ({} hits)",
            t_str,
            t_member,
            t_locate,
            idxs.len(),
            t_insn,
            t_scan,
            matches.len(),
            (insn.code_item_end() - insn.code_item_start()) / 1024,
            t_resolve,
            hits
        );
    }
}
