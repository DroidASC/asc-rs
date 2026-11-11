//! Listings of hand-built files: layout details that real samples do not
//! pin down, and damaged input.

mod common;

use asc_abc::leb128::write_uleb128;
use asc_abc::{Abc, ClassEntry};
use asc_arkisa::{Instruction, walk};
use asc_fixture::abc::{AbcBuilder, AbcCode, AbcDebugInfo, AbcFunction, AbcLineOp, AbcRecord, Asm};
use asc_pasm::{Options, SourceLine, write_function, write_instruction, write_record};

const RECORD: &str = "&entry/src/main/ets/pages/Index&";

/// A function of the synthetic record.
struct Function {
    name: &'static str,
    vregs: u32,
    code: Vec<u8>,
    /// `(start_pc, length, handler_pc, handler_size)` of catch-all try blocks.
    tries: Vec<[u32; 4]>,
}

impl Function {
    fn new(name: &'static str, code: &[u8]) -> Function {
        Function { name, vregs: 1, code: code.to_vec(), tries: Vec::new() }
    }
}

/// Little-endian byte sink.
#[derive(Default)]
struct Sink(Vec<u8>);

impl Sink {
    fn pos(&self) -> u32 {
        u32::try_from(self.0.len()).unwrap()
    }

    fn u8(&mut self, v: u8) -> &mut Sink {
        self.0.push(v);
        self
    }

    fn u16(&mut self, v: u16) -> &mut Sink {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn u32(&mut self, v: u32) -> &mut Sink {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn uleb(&mut self, v: u32) -> &mut Sink {
        write_uleb128(&mut self.0, v);
        self
    }

    fn bytes(&mut self, v: &[u8]) -> &mut Sink {
        self.0.extend_from_slice(v);
        self
    }

    /// An ASCII `String` item; returns its offset.
    fn string(&mut self, s: &str) -> u32 {
        let off = self.pos();
        self.uleb(u32::try_from(s.len()).unwrap() << 1 | 1).bytes(s.as_bytes()).u8(0);
        off
    }

    fn patch_u32(&mut self, at: u32, v: u32) {
        self.0[at as usize..at as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// Ids the instructions of a synthetic function can use.
mod id {
    pub const HELLO: u8 = 0;
    pub const ESCAPES: u8 = 1;
    /// Twenty integers: 0, 100, 200 …
    pub const NUMBERS: u8 = 2;
    /// The first function of the record.
    pub const FIRST_FUNCTION: u8 = 3;
    pub const MIXED: u8 = 4;
    /// Points outside the file.
    pub const DANGLING: u8 = 5;
    pub const COUNT: u32 = 6;
}

/// A one-region file, version 13.0.1.0 (no literal array index), holding one
/// module record with `functions`.
fn build(functions: &[Function]) -> Vec<u8> {
    let mut s = Sink::default();
    s.bytes(&asc_abc::MAGIC).u32(0).bytes(&[13, 0, 1, 0]);
    s.bytes(&[0; 44]);
    let class_index = s.pos();
    s.u32(0);
    let region_header = s.pos();
    s.bytes(&[0; 40]);
    let class_table = s.pos();
    s.bytes(&[0; 8]);
    let entity_table = s.pos();
    s.bytes(&[0; 4 * id::COUNT as usize]);

    let str_hello = s.string("hello");
    let str_escapes = s.string("say \"hi\"\n");
    let str_request = s.string("@ohos:hilog");
    let str_default = s.string("default");
    let str_hilog = s.string("hilog");
    let str_ns = s.string("ns");
    let str_index = s.string("Index");
    let str_key = s.string("k");
    let field_names = [s.string("moduleRecordIdx"), s.string("scopeNames"), s.string("moduleRequestPhaseIdx")];
    let function_names: Vec<u32> = functions.iter().map(|function| s.string(function.name)).collect();

    let numbers = s.pos();
    s.u32(40);
    for i in 0..20 {
        s.u8(0x02).u32(i * 100);
    }
    let nested = s.pos();
    s.u32(2).u8(0x01).u8(1);
    let mixed = s.pos();
    s.u32(16);
    s.u8(0x05).u32(str_key);
    s.u8(0x02).u32(0x1d4b42);
    s.u8(0x01).u8(1);
    s.u8(0x04).bytes(&1.5f64.to_le_bytes());
    s.u8(0xff).u8(0);
    s.u8(0x06);
    let mixed_method_slot = s.pos();
    s.u32(0);
    s.u8(0x09).u16(1);
    s.u8(0x18).u32(nested);
    // One phase byte per module request, without tags.
    let phases = s.pos();
    s.u32(1).u8(1);
    let scope_names = s.pos();
    s.u32(2).u8(0x05).u32(str_index);
    let module_record = s.pos();
    s.u32(0).u32(1).u32(str_request);
    s.u32(1).u32(str_hilog).u32(str_default).u16(0);
    s.u32(1).u32(str_ns).u16(0);
    s.u32(1).u32(str_index).u32(str_default);
    s.u32(0).u32(0);

    let codes: Vec<u32> = functions
        .iter()
        .map(|function| {
            let off = s.pos();
            s.uleb(function.vregs)
                .uleb(3)
                .uleb(u32::try_from(function.code.len()).unwrap())
                .uleb(u32::try_from(function.tries.len()).unwrap());
            s.bytes(&function.code);
            for &[start, length, handler, handler_size] in &function.tries {
                s.uleb(start).uleb(length).uleb(1).uleb(0).uleb(handler).uleb(handler_size);
            }
            off
        })
        .collect();

    let region_start = s.pos();
    let class = s.string(&format!("L{RECORD};"));
    s.u32(0).uleb(0x1).uleb(3).uleb(u32::try_from(functions.len()).unwrap());
    s.u8(0x00);
    s.u16(1).u16(0).u32(field_names[0]).uleb(0).u8(0x02).u32(module_record).u8(0x00);
    s.u16(1).u16(0).u32(field_names[1]).uleb(0).u8(0x02).u32(scope_names).u8(0x00);
    s.u16(1).u16(0).u32(field_names[2]).uleb(0).u8(0x02).u32(phases).u8(0x00);
    let mut first_method = 0;
    for (i, (name, code)) in function_names.iter().zip(&codes).enumerate() {
        if i == 0 {
            first_method = s.pos();
        }
        s.u16(1).u16(0).u32(*name).uleb(0x0108).u8(0x01).u32(*code).u8(0x00);
    }
    let region_end = s.pos();

    s.patch_u32(mixed_method_slot, first_method);
    s.patch_u32(class_index, class);
    for (i, entry) in [0x06, class].into_iter().enumerate() {
        s.patch_u32(class_table + 4 * u32::try_from(i).unwrap(), entry);
    }
    let entities = [str_hello, str_escapes, numbers, first_method, mixed, 0x7fff_ffff];
    assert_eq!(entities.len(), id::COUNT as usize);
    for (i, entry) in entities.into_iter().enumerate() {
        s.patch_u32(entity_table + 4 * u32::try_from(i).unwrap(), entry);
    }
    let region = [region_start, region_end, 2, class_table, id::COUNT, entity_table, u32::MAX, u32::MAX, u32::MAX, u32::MAX];
    for (i, word) in region.into_iter().enumerate() {
        s.patch_u32(region_header + 4 * u32::try_from(i).unwrap(), word);
    }
    let file_size = s.pos();
    let header = [file_size, file_size, 0, 1, class_index, 0, class_index, u32::MAX, u32::MAX, 1, region_header];
    for (i, word) in header.into_iter().enumerate() {
        s.patch_u32(16 + 4 * u32::try_from(i).unwrap(), word);
    }
    s.0
}

fn listing_with(functions: &[Function], opts: &Options) -> String {
    let data = build(functions);
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(RECORD.as_bytes()).unwrap().unwrap().local().unwrap();
    let mut text = String::new();
    write_record(&mut text, &abc, &class, opts).unwrap();
    text
}

fn listing(functions: &[Function]) -> String {
    listing_with(functions, &Options::default())
}

/// The lines of the first function's listing, header and `.end` excluded.
fn body(text: &str) -> Vec<&str> {
    let start = text.find(".function ").unwrap();
    text[start..].lines().skip(2).take_while(|line| *line != ".end function").collect()
}

#[test]
fn record_header_fields_and_function_frame() {
    let text = listing(&[Function::new("#~@0>#build", &[0x65]), Function::new("func_main_0", &[0x65])]);
    assert_eq!(
        text,
        "\
.record &entry/src/main/ets/pages/Index&
; module, package entry, 3 fields, 2 functions
.module
  requests:
    0: \"@ohos:hilog\"  ; phase 1
  regular imports:  ; ldexternalmodulevar N
    0: import { default as hilog } from \"@ohos:hilog\"
  namespace imports:
    0: import * as ns from \"@ohos:hilog\"
  local exports:  ; ldlocalmodulevar N, stmodulevar N
    0: export { Index as default }
.field u32 moduleRecordIdx = @0x1b7
.field u32 scopeNames = [ \"Index\" ]
.field u32 moduleRequestPhaseIdx = [ 1 ]

.function #~@0>#build  ; Index.build
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 1 byte
  0000  returnundefined
.end function

.function func_main_0
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 1 byte
  0000  returnundefined
.end function
"
    );
}

#[test]
fn labels_sit_at_branch_targets_and_try_bounds() {
    let mut function = Function::new(
        "#~@0>#build",
        &[
            0x3e, 0x00, 0x00, // 0000 lda.str "hello"
            0x4f, 0x07, // 0003 jeqz +7
            0x62, 0x42, 0x4b, 0x1d, 0x00, // 0005 ldai 1919810
            0x61, 0x00, // 000a sta v0
            0x4d, 0xf4, // 000c jmp -12
            0x65, // 000e returnundefined
        ],
    );
    function.tries = vec![[5, 5, 0x0e, 1]];
    assert_eq!(
        listing(&[function]).split_once("\n\n").unwrap().1,
        "\
.function #~@0>#build  ; Index.build
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 15 bytes, 1 try block
L_0000:
  0000  lda.str \"hello\"
  0003  jeqz L_000a
  .try 0 [0005, 000a) catchall -> L_000e
  0005  ldai 0x1d4b42 (1919810)
  .endtry 0
L_000a:
  000a  sta v0
  000c  jmp L_0000
L_000e:  ; handler of try 0, 1 byte
  000e  returnundefined
.end function
"
    );
}

#[test]
fn a_try_range_may_end_with_the_code() {
    let mut function = Function::new("f", &[0x00, 0x65]);
    function.tries = vec![[0, 2, 1, 1], [1, 0, 1, 0]];
    assert_eq!(
        body(&listing(&[function])),
        [
            "  .try 0 [0000, 0002) catchall -> L_0001",
            "  0000  ldundefined",
            "L_0001:  ; handler of try 0, 1 byte  ; handler of try 1, 0 bytes",
            "  .try 1 [0001, 0001) catchall -> L_0001  ; empty",
            "  0001  returnundefined",
            "  .endtry 0",
        ]
    );
}

#[test]
fn operands_are_resolved_in_place() {
    let mut code = vec![
        0x44,
        0x10, // mov v0, a0
        0x3e,
        id::ESCAPES,
        0x00, // lda.str
        0x06,
        0x09,
        id::NUMBERS,
        0x00, // createarraywithbuffer
        0x07,
        0x09,
        id::MIXED,
        0x00, // createobjectwithbuffer
        0x33,
        0x09,
        id::FIRST_FUNCTION,
        0x00,
        0x02, // definefunc
        0x7e,
        0x00, // ldexternalmodulevar 0
        0x7b,
        0x00, // getmodulenamespace 0
        0x7c,
        0x00, // stmodulevar 0
        0x7d,
        0x00, // ldlocalmodulevar 0
        0x62,
        0xb9,
        0x79,
        0x37,
        0x9e, // ldai -1640531527
        0x09,
        0x0c, // newlexenv 12
        0x73,
        0x09,
        0x03,
        0x01, // callrange 3, a0
        0x31,
        0x09,
        0x02,
        0x00, // callthisrange 2, v0
    ];
    code.push(0x63); // fldai 0.5
    code.extend_from_slice(&0.5f64.to_le_bytes());
    code.push(0x65);
    let text = listing_with(&[Function::new("#~@0>#build", &code)], &Options { literal_limit: 8, ..Options::default() });
    assert_eq!(
        body(&text),
        [
            "  0000  mov v0, a0",
            "  0002  lda.str \"say \\\"hi\\\"\\n\"",
            "  0005  createarraywithbuffer [ 0, 0x64 (100), 0xc8 (200), 0x12c (300), 0x190 (400), 0x1f4 (500), 0x258 (600), 0x2bc (700), … (+12 more) ]",
            "  0009  createobjectwithbuffer [ \"k\", 0x1d4b42 (1919810), true, 1.5, null, method:#~@0>#build, method_affiliate:1, literal_array:@0x16e ]",
            "  000d  definefunc #~@0>#build, 2  ; Index.build",
            "  0012  ldexternalmodulevar 0  ; import { default as hilog } from \"@ohos:hilog\"",
            "  0014  getmodulenamespace 0  ; import * as ns from \"@ohos:hilog\"",
            "  0016  stmodulevar 0  ; export { Index as default }",
            "  0018  ldlocalmodulevar 0  ; export { Index as default }",
            "  001a  ldai -1640531527 (u32 0x9e3779b9)",
            "  001f  newlexenv 0xc (12)",
            "  0021  callrange 3, a0  ; a0..a2",
            "  0025  callthisrange 2, v0  ; v0..a1",
            "  0029  fldai 0.5",
            "  0032  returnundefined",
        ]
    );

    // Inline-cache slots come back on request, where `isa.yaml` puts them.
    let text = listing_with(
        &[Function::new("f", &[0x33, 0x09, id::FIRST_FUNCTION, 0x00, 0x02])],
        &Options { ic_slots: true, ..Options::default() },
    );
    assert_eq!(body(&text), ["  0000  definefunc 0x9, f, 2"]);
}

#[test]
fn literal_arrays_are_bounded() {
    let code = [0x06, 0x00, id::NUMBERS, 0x00];
    let line = |limit: usize| {
        let text = listing_with(&[Function::new("f", &code)], &Options { literal_limit: limit, ..Options::default() });
        body(&text)[0].to_owned()
    };
    assert_eq!(line(0), "  0000  createarraywithbuffer [ … (+20 more) ]");
    assert_eq!(line(2), "  0000  createarraywithbuffer [ 0, 0x64 (100), … (+18 more) ]");
    assert_eq!(line(19).matches(", ").count(), 19);
    assert!(line(19).ends_with(", 0x708 (1800), … (+1 more) ]"));
    for limit in [20, 21, Options::DEFAULT_LITERAL_LIMIT, usize::MAX] {
        assert!(line(limit).ends_with(", 0x708 (1800), 0x76c (1900) ]"), "{limit}");
        assert!(!line(limit).contains('…'), "{limit}");
    }
}

#[test]
fn unresolvable_operands_are_marked_where_they_stand() {
    let text = listing(&[Function::new(
        "f",
        &[
            0x3e,
            id::DANGLING,
            0x00, // lda.str: offset outside the file
            0x3e,
            0x63,
            0x00, // lda.str: id outside the region index
            0x06,
            0x00,
            id::DANGLING,
            0x00, // createarraywithbuffer
            0x33,
            0x00,
            id::HELLO,
            0x00,
            0x00, // definefunc naming a string
            0x7e,
            0x07, // ldexternalmodulevar 7
            0x7c,
            0x07, // stmodulevar 7
            0x7b,
            0x07, // getmodulenamespace 7
            0x4d,
            0x80, // jmp -128
            0x65,
        ],
    )]);
    let lines = body(&text);
    assert_eq!(lines[0], "  0000  lda.str <error: string id 0x5: string offset 0x7fffffff is outside the file body>");
    assert_eq!(lines[1], "  0003  lda.str <error: string id 0x63: region method index index 99 out of range (size 6)>");
    assert_eq!(
        lines[2],
        "  0006  createarraywithbuffer <error: literal array @0x7fffffff: literal array offset 0x7fffffff is outside the file body>"
    );
    assert!(lines[3].starts_with("  000a  definefunc "), "{}", lines[3]);
    assert_eq!(lines[4], "  000f  ldexternalmodulevar 7  ; <error: no regular import 7, the module has 1>");
    assert_eq!(lines[5], "  0011  stmodulevar 7  ; <error: no local export 7, the module has 1>");
    assert_eq!(lines[6], "  0013  getmodulenamespace 7  ; <error: no module request 7, the module has 1>");
    assert_eq!(lines[7], "  0015  jmp <error: jump by -128 to before the code>");
    assert_eq!(lines[8], "  0017  returnundefined");
    assert!(text.ends_with(".end function\n"));
}

#[test]
fn branches_that_miss_an_instruction_are_reported() {
    let text = listing(&[Function::new(
        "f",
        &[
            0x4d, 0x03, // 0000 jmp +3: into the middle of the next instruction
            0x62, 0x00, 0x00, 0x00, 0x00, // 0002 ldai 0
            0x4d, 0x40, // 0007 jmp +64: past the end
            0x65, // 0009
        ],
    )]);
    assert_eq!(
        body(&text),
        [
            "  0000  jmp L_0003",
            "  0002  ldai 0",
            "  ; <error: branch or handler target 0x0003 is not the start of an instruction>",
            "  0007  jmp L_0047",
            "  0009  returnundefined",
            "  ; <error: branch or handler target 0x0047 is past the end of the code>",
        ]
    );

    let mut function = Function::new("f", &[0x62, 0x00, 0x00, 0x00, 0x00, 0x65]);
    function.tries = vec![[1, 2, 5, 1], [0, 3, 5, 1]];
    assert_eq!(
        body(&listing(&[function])),
        [
            "  .try 1 [0000, 0003) catchall -> L_0005",
            "  0000  ldai 0",
            "L_0005:  ; handler of try 0, 1 byte  ; handler of try 1, 1 byte",
            "  0005  returnundefined",
            "  ; <error: try 0 [0001, 0003): its start is not the start of an instruction>",
            "  ; <error: try 1 [0000, 0003): its end is not the start of an instruction>",
        ]
    );
}

#[test]
fn undecodable_code_ends_one_listing_only() {
    let text = listing(&[
        Function::new("bad_opcode", &[0x00, 0xe2, 0x65, 0x65]),
        Function::new("cut_short", &[0x00, 0x62, 0x01]),
        Function::new("bad_prefixed", &[0xfe, 0x7f]),
        Function::new("fine", &[0x65]),
    ]);
    let functions: Vec<&str> = text.split("\n\n").skip(1).collect();
    assert_eq!(
        functions,
        [
            "\
.function bad_opcode
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 4 bytes
  0000  ldundefined
  ; <error: undefined opcode 0xe2 at offset 0x1; listing stops, 3 of 4 bytes not disassembled>
.end function",
            "\
.function cut_short
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 3 bytes
  0000  ldundefined
  ; <error: instruction at offset 0x1 runs past the end of the code; listing stops, 2 of 3 bytes not disassembled>
.end function",
            "\
.function bad_prefixed
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 2 bytes
  ; <error: undefined opcode 0xfe 0x7f at offset 0x0; listing stops, 2 of 2 bytes not disassembled>
.end function",
            "\
.function fine
; vregs 1, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 1 byte
  0000  returnundefined
.end function
",
        ]
    );
}

#[test]
fn one_function_and_one_instruction_match_the_record_listing() {
    let data = build(&[Function::new("#~@0>#build", &[0x33, 0x00, id::FIRST_FUNCTION, 0x00, 0x01, 0x7e, 0x00, 0x4d, 0x00, 0x60, 0x01])]);
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(RECORD.as_bytes()).unwrap().unwrap().local().unwrap();
    let method = class.methods().unwrap().next().unwrap().unwrap();
    let opts = Options::default();

    let (mut record, mut function) = (String::new(), String::new());
    write_record(&mut record, &abc, &class, &opts).unwrap();
    write_function(&mut function, &abc, &class, &method, &opts).unwrap();
    assert!(record.ends_with(&format!("\n\n{function}")));

    let code = method.code().unwrap().unwrap();
    let alone: Vec<String> = walk(code.instructions())
        .map(|insn| {
            let mut text = String::new();
            write_instruction(&mut text, &abc, &method, &insn.unwrap(), &opts).unwrap();
            text
        })
        .collect();
    assert_eq!(
        alone,
        [
            "definefunc #~@0>#build, 1  ; Index.build",
            "ldexternalmodulevar 0  ; import { default as hilog } from \"@ohos:hilog\"",
            "jmp L_0007",
            // vregs is 1: register 1 is the first argument.
            "lda a0"
        ]
    );
    for line in &alone {
        assert!(function.contains(&format!("  {line}\n")), "{line}");
    }
}

/// xorshift64, enough for reproducible damage without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound as u64).unwrap()
    }
}

/// Render everything that still parses; the result does not matter, only
/// that nothing panics and that every listing is closed.
fn render_damaged(data: &[u8]) {
    let Ok(abc) = Abc::parse_lenient(data) else { return };
    let Ok(classes) = abc.classes() else { return };
    let opts = Options { lines: true, locals: true, ic_slots: true, ..Options::default() };
    let mut text = String::new();
    for entry in classes {
        let Ok(ClassEntry::Local(class)) = entry else { continue };
        text.clear();
        write_record(&mut text, &abc, &class, &opts).unwrap();
        assert_eq!(text.matches("\n.function ").count(), text.matches("\n.end function\n").count());
        let Ok(methods) = class.methods() else { continue };
        for method in methods.map_while(Result::ok) {
            text.clear();
            write_function(&mut text, &abc, &class, &method, &opts).unwrap();
            let Ok(Some(code)) = method.code() else { continue };
            for insn in walk(code.instructions()).map_while(Result::ok).take(64) {
                text.clear();
                write_instruction(&mut text, &abc, &method, &insn, &opts).unwrap();
                assert!(!text.contains('\n'));
            }
        }
    }
}

fn damage(data: &[u8], rounds: usize, seed: u64) {
    let mut rng = Rng(seed);
    for _ in 0..rounds {
        let mut copy = data.to_vec();
        for _ in 0..=rng.below(4) {
            let at = asc_abc::HEADER_SIZE + rng.below(copy.len() - asc_abc::HEADER_SIZE);
            copy[at] = match rng.below(4) {
                0 => 0xff,
                1 => 0x00,
                _ => rng.next().to_le_bytes()[0],
            };
        }
        render_damaged(&copy);
    }
    // Truncation at every length (or a sample of them for a large file).
    let step = (data.len() / 400).max(1);
    for len in (0..data.len()).step_by(step) {
        render_damaged(&data[..len]);
    }
}

#[test]
fn damaged_files_never_panic() {
    let mut code = vec![0x3e, id::ESCAPES, 0x00, 0x06, 0x00, id::NUMBERS, 0x00, 0x07, 0x00, id::MIXED, 0x00];
    code.extend_from_slice(&[0x33, 0x00, id::FIRST_FUNCTION, 0x00, 0x02, 0x7e, 0x00, 0x7b, 0x00, 0x7c, 0x00, 0x4f, 0x02, 0x65]);
    let mut function = Function::new("#~@0>#build", &code);
    function.tries = vec![[3, 8, 0x18, 1]];
    let data = build(&[function, Function::new("func_main_0", &[0x4d, 0x00, 0x65])]);
    render_damaged(&data);
    damage(&data, 5_000, 0x9e37_79b9_7f4a_7c15);
}

/// The listing of the one function of a file whose debug info is `debug`.
fn listing_with_debug(debug: AbcDebugInfo, damage: impl FnOnce(&mut Vec<u8>, &Abc<'_>)) -> String {
    let mut code = Asm::new();
    code.op("ldundefined", []).op("sta", [0.into()]).op("lda", [0.into()]).op("return", []);
    let mut builder = AbcBuilder::new();
    builder.record(AbcRecord::new(RECORD).function(AbcFunction::new("#*#named", AbcCode::new(3, 5, code)).debug(debug)));
    let mut data = builder.build().bytes;
    let pristine = data.clone();
    damage(&mut data, &Abc::parse(&pristine).unwrap());
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(RECORD.as_bytes()).unwrap().unwrap().local().unwrap();
    let method = class.methods().unwrap().next().unwrap().unwrap();
    let mut text = String::new();
    write_function(&mut text, &abc, &class, &method, &Options { locals: true, ..Options::default() }).unwrap();
    text
}

#[test]
fn registers_are_named_from_the_debug_info() {
    let local = |reg: i32, name: &str| AbcLineOp::StartLocal { reg, name: name.to_owned(), ty: "any".to_owned() };
    let debug = AbcDebugInfo {
        line_start: 4,
        params: vec![Some("url".to_owned()), None],
        program: vec![
            local(0, "count"),
            AbcLineOp::StartLocalExtended { reg: 1, name: "na\nme".to_owned(), ty: "any".to_owned(), signature: "Lstring;".to_owned() },
            AbcLineOp::Special { pc_delta: 1, line_delta: 1 },
            local(2, "item"),
            local(-1, "result"),
            local(4, "that"),
            AbcLineOp::Special { pc_delta: 2, line_delta: 1 },
            AbcLineOp::EndLocal(2),
        ],
    };
    let text = listing_with_debug(debug.clone(), |_, _| {});
    let header: Vec<&str> = text.lines().take_while(|line| !line.starts_with("  ")).collect();
    assert_eq!(
        header,
        [
            ".function #*#named  ; named",
            "; vregs 3, args 5 (a0 func, a1 new.target, a2 this, 2 params), code 6 bytes, line 4",
            // Variables that share a range share a line; one left open lives to the end of the code.
            "; locals [0000, 0006): v0 count, v1 na\\nme: Lstring;",
            "; locals [0001, 0003): v2 item",
            "; locals [0001, 0006): acc result, a1 that",
            // The nameless second parameter is left out.
            "; params: a0 url",
        ]
    );
    // Without names the header is the two lines it was.
    let plain = listing_with_debug(AbcDebugInfo { program: Vec::new(), params: Vec::new(), ..debug.clone() }, |_, _| {});
    assert_eq!(plain.lines().take_while(|line| !line.starts_with("  ")).count(), 2, "{plain}");

    // More variables than a header shows.
    let many = AbcDebugInfo { line_start: 1, params: Vec::new(), program: (0..300).map(|_| local(0, "count")).collect() };
    let text = listing_with_debug(many, |_, _| {});
    let lines: Vec<&str> = text.lines().filter(|line| line.starts_with("; locals")).collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(lines[0].matches("v0 count").count(), 256);
    assert_eq!(lines[1], "; locals: … (+44 more)");

    // A program that runs out of constants is reported in place of the
    // names: twelve operations taking one each, where the pool holds eleven.
    let text = listing_with_debug(debug, |data, abc| {
        let class = abc.find_record(RECORD.as_bytes()).unwrap().unwrap().local().unwrap();
        let info = class.methods().unwrap().next().unwrap().unwrap().debug_info().unwrap().unwrap();
        let program = info.line_program_off().unwrap() as usize;
        data[program..program + 12].fill(0x0b);
    });
    assert!(text.contains("\n; locals: <error: "), "{text}");
    assert!(text.ends_with(".end function\n"));
}

#[test]
fn damaged_sample_never_panics() {
    let Some(data) = common::load_sample("Bridge.hap") else { return };
    damage(&data, 100, 0x2545_f491_4f6c_dd1d);
}

#[test]
fn every_opcode_renders_with_any_operands() {
    let data = build(&[Function::new("f", &[0x65])]);
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(RECORD.as_bytes()).unwrap().unwrap().local().unwrap();
    let method = class.methods().unwrap().next().unwrap().unwrap();
    let opts = Options { ic_slots: true, ..Options::default() };
    let mut text = String::new();
    for fill in [0x00, 0x01, 0x7f, 0x80, 0xff] {
        for opcode in asc_arkisa::opcodes() {
            let mut code = vec![fill; opcode.byte_len()];
            match opcode.prefix {
                None => code[0] = opcode.value,
                Some(prefix) => code[..2].copy_from_slice(&[prefix.byte(), opcode.value]),
            }
            let insn = Instruction::decode(&code, 0).unwrap();
            text.clear();
            write_instruction(&mut text, &abc, &method, &insn, &opts).unwrap();
            assert!(text.starts_with(opcode.name), "{text}");
            // One token per operand: nothing is dropped, nothing breaks the line.
            assert!(!text.contains('\n'), "{text}");
            let operands = text[opcode.name.len()..].split("  ; ").next().unwrap();
            assert_eq!(operands.is_empty(), opcode.operands.is_empty(), "{text}");
        }
    }
}

/// What a source map says of the lines of the debug info: the record
/// names the file, each function its source line, the first one it has.
#[test]
fn source_lines_follow_the_lines_of_the_debug_info() {
    let mut code = Asm::new();
    code.op("ldundefined", []).op("sta", [0.into()]).op("lda", [0.into()]).op("return", []);
    let mut builder = AbcBuilder::new();
    let function = AbcFunction::new("#*#named", AbcCode::new(3, 5, code)).debug(AbcDebugInfo::rows("a.ets", 4, &[(0, 4), (1, 5), (3, 7)]));
    builder.record(AbcRecord::new(RECORD).function(function));
    let data = builder.build().bytes;
    let abc = Abc::parse(&data).unwrap();
    let class = abc.find_record(RECORD.as_bytes()).unwrap().unwrap().local().unwrap();
    let method = class.methods().unwrap().next().unwrap().unwrap();
    let files = ["src/a file.ets".to_owned(), "src/unused.ets".to_owned(), "src/part.ets".to_owned()];
    let listing = |named: &[u32], lines: &[Option<SourceLine>], whole: bool, every_line: bool| {
        let source = asc_pasm::SourceLines { files: &files, named, lines };
        let opts = Options { source: Some(source), lines: every_line, ..Options::default() };
        let mut text = String::new();
        if whole {
            write_record(&mut text, &abc, &class, &opts).unwrap();
        } else {
            write_function(&mut text, &abc, &class, &method, &opts).unwrap();
        }
        text
    };
    let first = |lines: &[Option<u32>]| -> Vec<Option<SourceLine>> {
        lines.iter().map(|line| line.map(|line| SourceLine { file: 0, line })).collect()
    };
    let header = |lines: &[Option<u32>], whole: bool, every_line: bool| listing(&[0], &first(lines), whole, every_line);
    let line_of = |text: &str| text.lines().find(|line| line.starts_with("; vregs")).unwrap().rsplit(", line ").next().unwrap().to_owned();

    // Line 4 of the compiled file is line 9 of the source.
    let mapped = [None, None, None, None, Some(9), Some(10)];
    let record = header(&mapped, true, false);
    assert!(record.lines().nth(2).unwrap().starts_with("; source src/a file.ets (by the source map: "), "{record}");
    assert_eq!(line_of(&record), "4 (source line 9)");
    // A function on its own says the same, below no header: the record's names the file.
    assert_eq!(line_of(&header(&mapped, false, false)), "4 (source line 9)");
    // The first line is the build's own: the next one that has a source stands for the function.
    let later = [None, None, None, None, None, Some(10)];
    assert_eq!(line_of(&header(&later, true, false)), "4 (source line 10 at line 5)");
    // No line of it has one, or the map ends before it.
    assert_eq!(line_of(&header(&[None; 8], true, false)), "4 (no source line)");
    assert_eq!(line_of(&header(&[Some(1)], false, false)), "4 (no source line)");
    // With every line in the listing, each says its own.
    let woven = header(&mapped, true, true);
    let lines: Vec<&str> = woven.lines().filter(|line| line.starts_with("  ; line ")).collect();
    assert_eq!(lines, ["  ; line 4 (source line 9)", "  ; line 5 (source line 10)", "  ; line 7"]);

    // A record made from several files numbers the ones lines come from; each line says which.
    let at = |file, line| Some(SourceLine { file, line });
    let several = [None, None, None, None, at(2, 9), at(0, 3), None, at(2, 11)];
    let record = listing(&[0, 2], &several, true, true);
    assert_eq!(
        record.lines().nth(2).unwrap(),
        "; sources #0 src/a file.ets, #2 src/part.ets (by the source map: \"line N\" of a function is a line of the compiled file, \
         from 0; \"source #K line N\" is line N of source #K)"
    );
    let lines: Vec<&str> = record.lines().filter(|line| line.starts_with("  ; line ")).collect();
    assert_eq!(lines, ["  ; line 4 (source #2 line 9)", "  ; line 5 (source #0 line 3)", "  ; line 7 (source #2 line 11)"]);
    assert_eq!(line_of(&listing(&[0, 2], &several, false, false)), "4 (source #2 line 9)");
    let later = [None, None, None, None, None, at(0, 3)];
    assert_eq!(line_of(&listing(&[0, 2], &later, false, false)), "4 (source #0 line 3 at line 5)");
    // Only so many are named.
    let many: Vec<u32> = (0..12).collect();
    let files: Vec<String> = many.iter().map(|index| format!("f{index}.ets")).collect();
    let source = asc_pasm::SourceLines { files: &files, named: &many, lines: &[] };
    let mut text = String::new();
    write_record(&mut text, &abc, &class, &Options { source: Some(source), ..Options::default() }).unwrap();
    assert!(
        text.lines().nth(2).unwrap().starts_with("; sources #0 f0.ets, #1 f1.ets, ") && text.contains(", #7 f7.ets, … (+4 more) (by "),
        "{text}"
    );
}
