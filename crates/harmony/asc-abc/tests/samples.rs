//! Tests over real HarmonyOS packages. The samples are not in the
//! repository: every test returns early when its file is absent.
//!
//! Locations: `$ASC_ABC_SAMPLES` (default `<workspace>/../ark/ReArk/samples`)
//! and `$ASC_ABC_LARGE_SAMPLE` (no default: a directory holding an app-store
//! `entry.hap` and its decrypted `modules.abc`).

mod common;

use std::time::Instant;

use asc_abc::{Abc, AbcError, ClassEntry, FunctionName, RecordName, Version};
use common::{Rng, Stats, load_large_sample, load_large_sample_entry, load_sample, walk};

/// Open strictly, check the checksum, and walk everything.
fn walk_sample(data: &[u8]) -> Stats {
    let abc = Abc::parse(data).unwrap();
    assert_eq!(abc.compute_checksum(), abc.header().checksum);
    assert_eq!(abc.header().file_size as usize, data.len());
    let started = Instant::now();
    let stats = walk(&abc, true).unwrap();
    println!("{} bytes, version {}, walked in {:?}: {stats:?}", data.len(), abc.header().version, started.elapsed());
    stats
}

fn record_names(abc: &Abc<'_>) -> Vec<String> {
    abc.classes().unwrap().map(|entry| String::from_utf8_lossy(entry.unwrap().name()).into_owned()).collect()
}

fn method_names(abc: &Abc<'_>, record: &str) -> Vec<String> {
    let class = abc.find_record(record.as_bytes()).unwrap().unwrap().local().unwrap();
    class.methods().unwrap().map(|method| method.unwrap().name().unwrap().to_str().into_owned()).collect()
}

#[test]
fn bridge() {
    let Some(data) = load_sample("Bridge.hap") else { return };
    let stats = walk_sample(&data);
    assert_eq!((stats.classes, stats.foreign_classes, stats.pseudo_records), (16, 0, 10));
    assert_eq!((stats.methods, stats.code_bytes, stats.try_blocks), (123, 14079, 22));
    assert_eq!((stats.module_records, stats.scope_name_tables), (6, 6));
    assert_eq!((stats.region_hint_mismatches, stats.methods_per_region.len()), (0, 1));

    let abc = Abc::parse(&data).unwrap();
    assert_eq!(abc.header().version, Version([13, 0, 1, 0]));
    // No literal array index in the header from 13.0.0.0 on.
    assert_eq!((abc.header().num_literalarrays, abc.header().literalarray_idx_off), (u32::MAX, u32::MAX));
    assert!(abc.literal_array_index().unwrap().is_none());

    let names = record_names(&abc);
    assert_eq!(names[0], "@ohos.app");
    assert_eq!(names[9], "_ESSlotNumberAnnotation");
    assert!(names.contains(&"com.hmos.exam5.pkg/entry/ets/pages/Home".to_owned()));
    assert_eq!(
        RecordName::parse(&names[10]),
        RecordName::Bundle { bundle: "com.hmos.exam5.pkg", module: "entry", path: "ets/entryability/EntryAbility" }
    );

    let class = abc.find_record(b"com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility").unwrap().unwrap().local().unwrap();
    assert_eq!((class.num_fields, class.num_methods), (6, 11));
    assert_eq!(class.package_name().unwrap(), Some(&b"entry"[..]));
    assert_eq!(class.scope_name(1).unwrap().unwrap().to_str(), "onWindowStageCreate");
    let methods = method_names(&abc, "com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility");
    assert_eq!(&methods[..4], ["#~@0>@1*#", "#~@0>@1*#^1", "#~@0>@1*#^2", "func_main_0"]);
    assert_eq!(class.restore_function_name("#~@0>@1*#^1"), "EntryAbility.onWindowStageCreate.<anonymous>^1");
    assert_eq!(class.restore_function_name("#~@0>#onCreate"), "EntryAbility.onCreate");
    assert_eq!(class.restore_function_name("#~@0=#EntryAbility"), "EntryAbility.constructor");

    let module = class.module_record().unwrap().unwrap();
    let text = |off: u32| abc.string(off).unwrap().to_str().into_owned();
    assert_eq!(
        module.requests.iter().map(text).collect::<Vec<_>>(),
        [
            "@ohos:app.ability.ConfigurationConstant",
            "@ohos:app.ability.UIAbility",
            "@ohos:hilog",
            "@bundle:com.hmos.exam5.pkg/entry/ets/model/DatabaseUtil"
        ]
    );
    let import = module.regular_imports.get(1).unwrap();
    assert_eq!(
        (text(import.import_name_off), text(import.local_name_off), import.module_request_idx),
        ("DatabaseManager".into(), "DatabaseManager".into(), 3)
    );
    let export = module.local_exports.get(0).unwrap();
    assert_eq!((text(export.local_name_off), text(export.export_name_off)), ("EntryAbility".into(), "default".into()));

    // `#~@0>#onCreate`: an instance method with code and a real first line.
    let on_create = class.methods().unwrap().map(Result::unwrap).find(|m| m.name().unwrap().bytes == b"#~@0>#onCreate").unwrap();
    assert_eq!(on_create.debug_info().unwrap().unwrap().first_line().unwrap(), Some(12));
    assert!(!on_create.code().unwrap().unwrap().instructions().is_empty());
}

#[test]
fn contacts() {
    let Some(data) = load_sample("contacts.hap") else { return };
    let stats = walk_sample(&data);
    assert_eq!((stats.classes, stats.foreign_classes, stats.pseudo_records), (25, 0, 9));
    assert_eq!(stats.region_hint_mismatches, 0);

    let abc = Abc::parse(&data).unwrap();
    assert_eq!(abc.header().version, Version([12, 0, 6, 0]));
    // The header index lists 1990 entries: literal arrays, module records and phase tables.
    assert_eq!(abc.literal_array_index().unwrap().unwrap().len(), 1990);
    assert_eq!((stats.literal_arrays, stats.module_records, stats.phase_tables), (1974, 16, 0));

    let names = record_names(&abc);
    assert!(names.contains(&"&entry/src/main/ets/pages/Index&".to_owned()), "{names:?}");
    let library = "&@ohos/jsonwebtoken/src/main/ets/dist/jsonwebtoken&1.0.1";
    assert_eq!(
        RecordName::parse(library),
        RecordName::Normalized { bundle: "", package: "@ohos/jsonwebtoken", path: "src/main/ets/dist/jsonwebtoken", version: "1.0.1" }
    );
    let class = abc.find_record(library.as_bytes()).unwrap().unwrap().local().unwrap();
    assert_eq!(class.num_methods, 5297);
    assert!(abc.find_record(b"&entry/src/main/ets/pages/Missing&").unwrap().is_none());
}

#[test]
fn yaoyao() {
    let Some(data) = load_sample("遥遥领先.hap") else { return };
    let stats = walk_sample(&data);
    assert_eq!((stats.classes, stats.methods, stats.code_bytes, stats.try_blocks), (16, 118, 9994, 2));
    assert_eq!((stats.module_records, stats.scope_name_tables), (7, 0));
    let abc = Abc::parse(&data).unwrap();
    assert_eq!(abc.header().version, Version([12, 0, 2, 0]));
    assert_eq!(abc.literal_array_index().unwrap().unwrap().len(), 46);
    let class = abc.find_record(b"com.lenovo.bridgeclone/entry/ets/pages/Home").unwrap().unwrap().local().unwrap();
    assert_eq!((class.num_fields, class.num_methods), (5, 38));
}

#[test]
fn easyhap() {
    let Some(data) = load_sample("EasyHap-default-unsigned.app") else { return };
    let stats = walk_sample(&data);
    assert_eq!((stats.classes, stats.foreign_classes, stats.methods, stats.code_bytes), (6, 1, 59, 5039));
    assert_eq!(stats.module_records, 3);

    let abc = Abc::parse(&data).unwrap();
    assert_eq!(abc.header().version, Version([9, 0, 0, 0]));
    // The one foreign entry of the class index.
    let foreign = abc.find_class(b"L_ESTypeAnnotation;").unwrap().unwrap();
    assert!(matches!(foreign, ClassEntry::Foreign(_)) && abc.header().is_foreign(foreign.offset()));
    // 9.0.0.0 predates scope chains: `#<number>#<name>` and plain names.
    let methods = method_names(&abc, "com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil");
    assert_eq!(methods.len(), 17);
    assert!(methods.contains(&"#1#".to_owned()) && methods.contains(&"encryptX".to_owned()), "{methods:?}");
    assert!(methods.iter().all(|name| !FunctionName::parse(name).is_scoped()));
    assert_eq!(FunctionName::parse("#1#").restore(|_| None), "<anonymous>");
}

#[test]
fn fpt() {
    let Some(data) = load_sample("fpt-default-signed.app") else { return };
    let stats = walk_sample(&data);
    assert_eq!((stats.classes, stats.pseudo_records), (22, 9));
    let abc = Abc::parse(&data).unwrap();
    assert_eq!(abc.header().version, Version([12, 0, 6, 0]));
    assert_eq!(abc.literal_array_index().unwrap().unwrap().len(), 151);
    let class = abc.find_record(b"&entry/src/main/ets/pages/AuthPage&").unwrap().unwrap().local().unwrap();
    assert_eq!(class.num_methods, 43);
}

#[test]
fn shctf() {
    let Some(data) = load_sample("shctf.app") else { return };
    let stats = walk_sample(&data);
    assert_eq!((stats.classes, stats.methods, stats.code_bytes, stats.try_blocks), (14, 41, 3895, 9));
    assert_eq!(stats.module_records, 5);
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(b"com.welcome.shctf/entry/ets/pages/Index").unwrap().unwrap().local().unwrap();
    assert_eq!(class.num_methods, 20);
    let module = class.module_record().unwrap().unwrap();
    let requests: Vec<_> = module.requests.iter().map(|off| abc.string(off).unwrap().to_str().into_owned()).collect();
    assert_eq!(
        requests,
        [
            "@bundle:com.welcome.shctf/entry/ets/model/maze",
            "@bundle:com.welcome.shctf/entry/ets/model/encode",
            "@ohos:promptAction",
            "@ohos:file.fs"
        ]
    );
}

/// The large sample: tens of megabytes, more than one region.
#[test]
fn large_sample_multi_region() {
    let Some(data) = load_large_sample() else { return };
    let stats = walk_sample(&data);
    let abc = Abc::parse(&data).unwrap();
    assert_eq!((stats.classes, stats.foreign_classes), (abc.header().num_classes, 0));
    // The index entries are literal arrays, module records and module request phase tables.
    let index_entries = abc.literal_array_index().unwrap().unwrap().len() as u64;
    assert_eq!(stats.literal_arrays + stats.module_records + stats.phase_tables, index_entries);

    let regions: Vec<_> = abc.regions().unwrap().iter().collect();
    assert!(regions.len() > 1, "{} region(s)", regions.len());
    // The regions are in file order, end to start, and none is empty.
    let ranges: Vec<_> = regions.iter().map(|r| (r.header().start, r.header().end)).collect();
    assert!(ranges.iter().all(|(start, end)| start < end), "{ranges:x?}");
    assert!(ranges.windows(2).all(|pair| pair[0].1 == pair[1].0), "{ranges:x?}");
    assert!(regions.iter().all(|r| (1..=0x1_0000).contains(&r.header().method_idx_size)));
    // Every method lies in the region its access flags name.
    assert_eq!(stats.region_hint_mismatches, 0);
    assert!(stats.methods_per_region.iter().all(|&count| count > 0), "{:?}", stats.methods_per_region);
    assert_eq!(stats.methods_per_region.iter().sum::<u64>(), stats.methods);

    // Reverse lookup agrees with forward resolution in every region.
    for region in &regions {
        let table = region.entity_table().unwrap();
        for idx in [0, table.len() / 2, table.len() - 1] {
            let off = table.get(idx).unwrap();
            let found = region.entity_idx(off).unwrap().unwrap();
            assert_eq!(region.entity_offset(found).unwrap(), off);
        }
    }
}

/// The same package as shipped: the 60-byte header is plain, the rest is
/// ciphertext.
#[test]
fn large_sample_encrypted_entry() {
    let Some(encrypted) = load_large_sample_entry("ets/modules.abc") else { return };
    let started = Instant::now();
    let err = Abc::parse(&encrypted).unwrap_err();
    println!("encrypted open rejected in {:?}: {err}", started.elapsed());
    let AbcError::Encrypted { stored, computed } = err else { panic!("{err}") };
    assert_ne!(stored, computed);

    // The header itself reads fine and matches the decrypted file's.
    let abc = Abc::parse_lenient(&encrypted).unwrap();
    assert!(abc.header().num_classes > 0 && abc.header().num_indexes > 0);
    if let Some(plain) = load_large_sample() {
        assert_eq!(abc.header(), Abc::parse(&plain).unwrap().header());
    }

    // A second, unencrypted abc in the same package.
    let widgets = load_large_sample_entry("ets/widgets.abc").unwrap();
    let stats = walk_sample(&widgets);
    assert_eq!(stats.methods_per_region.len(), 1);
}

/// Deterministic mutations of a real file: flipped bytes and truncations
/// must produce errors or different answers, never a panic or a hang.
#[test]
fn mutations_of_a_real_file_never_panic() {
    let Some(data) = load_sample("Bridge.hap") else { return };
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let rounds = if cfg!(debug_assertions) { 300 } else { 3000 };
    let (mut opened, mut walked) = (0, 0);
    for round in 0..rounds {
        let mut mutated = data.clone();
        match round % 4 {
            // A few flips in the index tables at the front, where they do the most damage.
            0 => {
                for _ in 0..3 {
                    let pos = 12 + rng.below(0x800);
                    mutated[pos] ^= 1 << rng.below(8);
                }
            }
            // Random bytes anywhere.
            1 | 2 => {
                for _ in 0..1 + rng.below(8) {
                    let pos = 12 + rng.below(mutated.len() - 12);
                    mutated[pos] = rng.next() as u8;
                }
            }
            _ => mutated.truncate(rng.below(mutated.len())),
        }
        let Ok(abc) = Abc::parse_lenient(&mutated) else { continue };
        opened += 1;
        let _ = abc.check_layout();
        walked += usize::from(walk(&abc, false).is_ok());
    }
    println!("{rounds} mutations: {opened} opened, {walked} walked without error");
    assert!(opened > rounds / 2);
}
