//! Disassembly of real HarmonyOS packages. The samples are not in the
//! repository: every test returns early when its file is absent.

mod common;

use std::fmt::Write as _;
use std::time::Instant;

use asc_abc::{Abc, Class, ClassEntry};
use asc_arkisa::walk;
use asc_pasm::{Options, write_function, write_instruction, write_record};
use common::{large_sample_dir, load_abc, load_sample};

fn record(abc: &Abc<'_>, name: &str) -> String {
    let class = abc.find_record(name.as_bytes()).unwrap().unwrap().local().unwrap();
    render(abc, &class, &Options::default())
}

fn render(abc: &Abc<'_>, class: &Class<'_>, opts: &Options) -> String {
    let mut text = String::new();
    write_record(&mut text, abc, class, opts).unwrap();
    text
}

/// The listing of the function whose raw name is `name`, header to `.end`.
fn function<'t>(record: &'t str, name: &str) -> &'t str {
    let start = record.find(&format!(".function {name}\n")).or_else(|| record.find(&format!(".function {name}  ;"))).unwrap();
    let rest = &record[start..];
    &rest[..rest.find(".end function\n").unwrap()]
}

/// An instruction line starts with its offset: two spaces, then hex digits.
fn is_instruction_line(line: &str) -> bool {
    line.strip_prefix("  ").is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_hexdigit()))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Totals {
    records: usize,
    functions: usize,
    instructions: usize,
    bytes: usize,
}

/// Disassemble every record and check each listing against the file: no
/// error marker, one closed `.function` per method, and as many instruction
/// lines as an independent walk of the code finds instructions, i.e. every
/// listing reaches the end of its code.
fn disassemble_all(label: &str, data: &[u8], check_parts: bool) -> Totals {
    let abc = Abc::parse(data).unwrap();
    let opts = Options::default();
    let mut totals = Totals::default();
    let mut text = String::new();
    let mut part = String::new();
    let started = Instant::now();
    for entry in abc.classes().unwrap() {
        let ClassEntry::Local(class) = entry.unwrap() else { continue };
        text.clear();
        write_record(&mut text, &abc, &class, &opts).unwrap();
        let name = String::from_utf8_lossy(class.name());
        assert!(!text.contains("<error"), "{name}: {}", text.lines().find(|line| line.contains("<error")).unwrap());
        assert!(text.starts_with(&format!(".record {name}\n")), "{name}");

        let mut listed = text.lines().filter(|line| is_instruction_line(line));
        let mut instructions = 0;
        for method in class.methods().unwrap() {
            let method = method.unwrap();
            if check_parts {
                part.clear();
                write_function(&mut part, &abc, &class, &method, &opts).unwrap();
                assert!(text.contains(part.as_str()), "{name}: {part}");
            }
            let Some(code) = method.code().unwrap() else { continue };
            let mut insns = walk(code.instructions());
            for insn in insns.by_ref() {
                let insn = insn.unwrap();
                instructions += 1;
                let line = listed.next().unwrap_or_else(|| panic!("{name}: the listing ends before {:#x}", insn.pc));
                if check_parts {
                    // The stand-alone rendering is the listing's line without its offset.
                    part.clear();
                    write!(&mut part, "  {:04x}  ", insn.pc).unwrap();
                    write_instruction(&mut part, &abc, &method, &insn, &opts).unwrap();
                    assert_eq!(line, part, "{name}");
                }
            }
            assert_eq!(insns.pc(), code.instructions().len());
        }
        assert_eq!(listed.next(), None, "{name}");
        let functions = text.lines().filter(|line| line.starts_with(".function ")).count();
        assert_eq!(functions, class.num_methods as usize, "{name}");
        assert_eq!(text.lines().filter(|line| *line == ".end function").count(), functions, "{name}");

        totals.records += 1;
        totals.functions += functions;
        totals.instructions += instructions;
        totals.bytes += text.len();
    }
    println!("{label}: {totals:?} in {:?} (with checks)", started.elapsed());
    totals
}

/// Time of the rendering alone, into one reused buffer: the whole file,
/// then its median-sized record on its own.
fn time_rendering(label: &str, data: &[u8]) {
    let abc = Abc::parse(data).unwrap();
    let opts = Options::default();
    let mut text = String::new();
    let mut sizes = Vec::new();
    let started = Instant::now();
    for entry in abc.classes().unwrap() {
        let ClassEntry::Local(class) = entry.unwrap() else { continue };
        text.clear();
        write_record(&mut text, &abc, &class, &opts).unwrap();
        sizes.push((text.len(), class));
    }
    let elapsed = started.elapsed();
    let bytes: usize = sizes.iter().map(|(size, _)| size).sum();
    println!("{label}: rendered {} records, {bytes} bytes in {elapsed:?}", sizes.len());

    sizes.sort_unstable_by_key(|(size, _)| *size);
    let name = |class: &Class<'_>| String::from_utf8_lossy(class.name()).into_owned();
    let (largest_size, largest) = sizes.last().unwrap();
    let (median_size, median) = &sizes[sizes.len() / 2];
    const ROUNDS: u32 = 200;
    let started = Instant::now();
    for _ in 0..ROUNDS {
        text.clear();
        write_record(&mut text, &abc, median, &opts).unwrap();
    }
    println!(
        "{label}: median record {} ({median_size} bytes, {} functions) in {:?}; largest {} ({largest_size} bytes)",
        name(median),
        median.num_methods,
        started.elapsed() / ROUNDS,
        name(largest)
    );
}

#[test]
fn bridge() {
    let Some(data) = load_sample("Bridge.hap") else { return };
    let totals = disassemble_all("Bridge.hap", &data, true);
    assert_eq!((totals.records, totals.functions), (16, 123));

    let abc = Abc::parse(&data).unwrap();
    let ability = record(&abc, "com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility");
    let header = "\
.record com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility
; module, package entry, 6 fields, 11 functions
.module
  requests:
    0: \"@ohos:app.ability.ConfigurationConstant\"
    1: \"@ohos:app.ability.UIAbility\"
    2: \"@ohos:hilog\"
    3: \"@bundle:com.hmos.exam5.pkg/entry/ets/model/DatabaseUtil\"
  regular imports:  ; ldexternalmodulevar N
    0: import { default as ConfigurationConstant } from \"@ohos:app.ability.ConfigurationConstant\"
    1: import { DatabaseManager } from \"@bundle:com.hmos.exam5.pkg/entry/ets/model/DatabaseUtil\"
    2: import { default as UIAbility } from \"@ohos:app.ability.UIAbility\"
    3: import { default as hilog } from \"@ohos:hilog\"
  local exports:  ; ldlocalmodulevar N, stmodulevar N
    0: export { EntryAbility as default }
.field u8 pkgName@entry = 0
.field u8 isCommonjs = 0
.field u8 hasTopLevelAwait = 0
.field u8 isSharedModule = 0
.field u32 scopeNames = [ \"EntryAbility\", \"onWindowStageCreate\" ]
.field u32 moduleRecordIdx = @0x5483

.function #~@0>@1*#  ; EntryAbility.onWindowStageCreate.<anonymous>
; vregs 7, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 33 bytes, line 27
  0000  mov v0, a0
  0002  mov v1, a1
  0004  mov v2, a2
  0006  tryldglobalbyname \"console\"
  000a  sta v5
  000c  lda v5
  000e  ldobjbyname \"info\"
  0012  sta v4
  0014  lda.str \"[EntryAbility] All databases initialized.\"
  0017  sta v6
  0019  lda v4
  001b  callthis1 v5, v6
  001f  ldundefined
  0020  returnundefined
.end function
";
    assert!(ability.starts_with(header), "{}", &ability[..header.len().min(ability.len())]);

    // A forward branch and its label; a module import; a range call whose note counts `this`.
    let closure = function(&ability, "#~@0>@1*#^2");
    assert!(closure.contains("\n  0016  jnez L_005d\n"));
    assert!(closure.contains(
        "\n  005c  returnundefined\nL_005d:\n  005d  ldexternalmodulevar 3  ; import { default as hilog } from \"@ohos:hilog\"\n"
    ));
    assert!(closure.contains("\n  0056  callthisrange 4, v6  ; v6..v10\n"));

    // A try range, its end, and the handler it names.
    let on_create = function(&ability, "#~@0>#onCreate");
    assert!(on_create.starts_with(
        ".function #~@0>#onCreate  ; EntryAbility.onCreate\n\
         ; vregs 15, args 5 (a0 func, a1 new.target, a2 this, 2 params), code 196 bytes, 1 try block, line 12\n"
    ));
    assert!(on_create.contains("\n  000b  mov v4, a4\n  .try 0 [000e, 004f) catchall -> L_0051\n  000e  lda v2\n"));
    assert!(
        on_create.contains(
            "\n  004b  callthis1 v7, v8\n  .endtry 0\n  004f  jmp L_0095\nL_0051:  ; handler of try 0, 68 bytes\n  0051  sta v6\n"
        )
    );

    // A method id with its restored name, and the class literal inline.
    let main = function(&ability, "func_main_0");
    assert!(main.contains(
        "defineclasswithbuffer #~@0=#EntryAbility, [ \"onCreate\", method:#~@0>#onCreate, method_affiliate:2, \"onDestroy\", method:#~@0>#onDestroy, method_affiliate:0, "
    ));
    assert!(main.contains(", 0, v6  ; EntryAbility.constructor\n"));
    assert!(main.contains("  stmodulevar 0  ; export { EntryAbility as default }\n"));

    let database = record(&abc, "com.hmos.exam5.pkg/entry/ets/model/DatabaseUtil");
    assert!(database.contains("  createobjectwithbuffer [ \"name\", \"user.db\", \"securityLevel\", null ]\n"));
    assert!(database.contains("  newobjrange 2, v6  ; v6..v7\n"));
}

#[test]
fn options_change_the_listing() {
    let Some(data) = load_sample("Bridge.hap") else { return };
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(b"com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility").unwrap().unwrap().local().unwrap();

    let slots = render(&abc, &class, &Options { ic_slots: true, ..Options::default() });
    assert!(slots.contains("\n  0006  tryldglobalbyname 0x0, \"console\"\n"));
    assert!(slots.contains("\n  000e  ldobjbyname 0x1, \"info\"\n"));
    assert!(slots.contains("\n  001b  callthis1 0x3, v5, v6\n"));

    let lines = render(&abc, &class, &Options { lines: true, ..Options::default() });
    let closure = function(&lines, "#~@0>@1*#");
    assert!(closure.contains("0 params), code 33 bytes\n"), "{closure}");
    assert!(closure.contains("\n  ; line 27\n  0006  tryldglobalbyname \"console\"\n"), "{closure}");
    // Line comments are the only difference.
    let without: String = lines.lines().filter(|line| !line.starts_with("  ; line ")).flat_map(|line| [line, "\n"]).collect();
    let plain: String = render(&abc, &class, &Options::default())
        .lines()
        .map(|line| line.split(", line ").next().unwrap())
        .flat_map(|line| [line, "\n"])
        .collect();
    assert_eq!(without, plain);

    let short = render(&abc, &class, &Options { literal_limit: 2, string_limit: 5, ..Options::default() });
    assert!(
        short.contains("defineclasswithbuffer #~@0=#EntryAbility, [ \"onCre\"… (+3 bytes), method:#~@0>#onCreate, … (+17 more) ], 0, v6")
    );
    assert!(short.contains("  lda.str \"[Entr\"… (+36 bytes)\n"));
}

#[test]
fn contacts() {
    let Some(data) = load_sample("contacts.hap") else { return };
    let totals = disassemble_all("contacts.hap", &data, false);
    assert_eq!((totals.records, totals.functions), (25, 5894));
    time_rendering("contacts.hap", &data);

    // `fldai` shows integral doubles in hex too.
    let abc = Abc::parse(&data).unwrap();
    let library = record(&abc, "&@ohos/crypto-js/src/main/js/crypto-js&2.0.0");
    assert!(library.contains("  fldai 3609767458.0 (0xd728ae22)\n"));
}

#[test]
fn yaoyao() {
    let Some(data) = load_sample("遥遥领先.hap") else { return };
    disassemble_all("遥遥领先.hap", &data, true);
}

/// Bytecode 9.0.0.0: numbered function names, no scope name table.
#[test]
fn easyhap() {
    let Some(data) = load_sample("EasyHap-default-unsigned.app") else { return };
    disassemble_all("EasyHap", &data, true);
    let abc = Abc::parse(&data).unwrap();
    let cipher = record(&abc, "com.zjuctf2024.easyhap/entry/ets/cipherUtil/CipherUtil");
    assert!(cipher.contains("\n.function #1#  ; <anonymous>\n"));
    assert!(cipher.contains("  ldexternalmodulevar 1  ; import { default as cryptoFramework } from \"@ohos:security.cryptoFramework\"\n"));
    assert!(cipher.contains("  definefunc #2#, 0  ; <anonymous>\n"));
    assert!(cipher.contains("  callthis3 v0, v2, a3, v3\n"));
}

#[test]
fn fpt() {
    let Some(data) = load_sample("fpt-default-signed.app") else { return };
    disassemble_all("fpt", &data, true);
}

#[test]
fn shctf() {
    let Some(data) = load_sample("shctf.app") else { return };
    disassemble_all("shctf", &data, true);
    let abc = Abc::parse(&data).unwrap();
    let mut all = String::new();
    for entry in abc.classes().unwrap() {
        if let ClassEntry::Local(class) = entry.unwrap() {
            write_record(&mut all, &abc, &class, &Options::default()).unwrap();
        }
    }
    // Constants in hex and decimal; an empty try range; a backward branch target.
    let encode = function(&all, "#9151489524504893103#encode");
    assert!(encode.contains("\n  0014  ldai 0x1d4b42 (1919810)\n  0019  sta v2\n  001b  ldai 0x1bf52 (114514)\n"), "{encode}");
    assert!(
        encode.contains("\n  .try 1 [0005, 0005) catchall -> L_0007  ; empty\n  0005  jmp L_000d\nL_0007:  ; handler of try 1, 0 bytes\n")
    );
    assert!(encode.contains("\nL_003f:\n  003f  lda v7\n"));
    assert!(encode.contains(" L_003f\n"));
    // An 85-item array fits under the default bound.
    assert!(all.lines().any(|line| line.contains("createarraywithbuffer [ \"#\", \"#\", ") && !line.contains('…')));
}

/// The large sample: every record disassembles, and the less common
/// module instructions carry the import they name.
#[test]
fn large_sample() {
    let Some(data) = large_sample_dir().and_then(|dir| std::fs::read(dir.join("modules.abc")).ok()) else { return };
    let totals = disassemble_all("large sample modules.abc", &data, false);
    assert!(totals.records > 0 && totals.functions >= totals.records);
    time_rendering("large sample modules.abc", &data);

    let abc = Abc::parse(&data).unwrap();
    let opts = Options::default();
    // The index spaces of the less common module instructions: each one
    // resolves to an import of the record, shown as a note.
    let mnemonics = [
        ("  getmodulenamespace ", "  ; import * as "),
        ("  wide.ldexternalmodulevar ", "  ; import { "),
        ("  callruntime.ldlazymodulevar ", "  ; import { "),
        ("  callruntime.ldsendableexternalmodulevar ", "  ; import { "),
    ];
    let mut text = String::new();
    let mut seen = [0usize; 4];
    for entry in abc.classes().unwrap() {
        let ClassEntry::Local(class) = entry.unwrap() else { continue };
        text.clear();
        write_record(&mut text, &abc, &class, &opts).unwrap();
        for line in text.lines().filter(|line| is_instruction_line(line)) {
            for (seen, (mnemonic, note)) in seen.iter_mut().zip(mnemonics) {
                if line.contains(mnemonic) {
                    assert!(line.contains(note), "{line}");
                    *seen += 1;
                }
            }
        }
    }
    println!(
        "module instructions with their imports: {:?}",
        mnemonics.iter().map(|(mnemonic, _)| mnemonic.trim()).zip(seen).collect::<Vec<_>>()
    );

    // The module request phase table is one byte per request, not a literal
    // array; a request with a phase says so.
    let lazy = (abc.classes().unwrap())
        .filter_map(|entry| entry.unwrap().local())
        .find(|class| class.module_request_phases().unwrap().is_some_and(|phases| phases.contains(&1)));
    if let Some(lazy) = lazy {
        let phases = lazy.module_request_phases().unwrap().unwrap();
        text.clear();
        write_record(&mut text, &abc, &lazy, &opts).unwrap();
        assert_eq!(text.lines().filter(|line| line.ends_with("\"  ; phase 1")).count(), phases.iter().filter(|&&phase| phase == 1).count());
        let listed = phases.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
        assert!(text.contains(&format!("\n.field u32 moduleRequestPhaseIdx = [ {listed} ]\n")));
    }
}

#[test]
fn large_sample_widgets() {
    let Some(data) = large_sample_dir().and_then(|dir| load_abc(&dir.join("entry.hap"), "ets/widgets.abc")) else { return };
    disassemble_all("large sample widgets.abc", &data, true);
}
