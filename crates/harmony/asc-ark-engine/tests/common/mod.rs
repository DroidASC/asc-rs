//! Shared test helpers.
//!
//! The synthetic ABC writer below is a copy of the one in
//! `crates/harmony/asc-abc/tests/common/mod.rs`; both should move onto the
//! shared writer in `asc-fixture` once it exists.

#![allow(dead_code)] // each test binary uses its own part

use std::path::{Path, PathBuf};

/// The workspace root (`crates/harmony/asc-ark-engine/../../..`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A ReArk sample: `$ASC_ABC_SAMPLES/<file>`, else
/// `<workspace>/../ark/ReArk/samples/<file>`. `None` when it is not there.
pub fn sample(file: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("ASC_ABC_SAMPLES").map_or_else(|| workspace_root().join("../ark/ReArk/samples"), PathBuf::from);
    Some(dir.join(file)).filter(|path| path.is_file())
}

/// The directory of the large sample, `$ASC_ABC_LARGE_SAMPLE`: an
/// app-store package `entry.hap` and its decrypted `modules.abc`. There is
/// no default: `None` unless the variable is set and both files are there.
pub fn large_sample_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("ASC_ABC_LARGE_SAMPLE")?);
    Some(dir).filter(|dir| dir.join("entry.hap").is_file() && dir.join("modules.abc").is_file())
}

/// `data` with everything after the 60-byte header scrambled: what an
/// app-store encrypted file looks like (plain header, checksum included).
pub fn encrypted(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (i, byte) in out.iter_mut().enumerate().skip(asc_abc::HEADER_SIZE) {
        *byte ^= 0xa5 ^ (i as u8).wrapping_mul(31);
    }
    out
}

#[derive(Default)]
pub struct Sink(pub Vec<u8>);

impl Sink {
    pub fn pos(&self) -> u32 {
        self.0.len() as u32
    }

    pub fn u8(&mut self, v: u8) -> &mut Sink {
        self.0.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Sink {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Sink {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn uleb(&mut self, v: u32) -> &mut Sink {
        asc_abc::leb128::write_uleb128(&mut self.0, v);
        self
    }

    pub fn sleb(&mut self, v: i32) -> &mut Sink {
        asc_abc::leb128::write_sleb128(&mut self.0, v);
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Sink {
        self.0.extend_from_slice(v);
        self
    }

    /// An ASCII `String` item; returns its offset.
    pub fn string(&mut self, s: &str) -> u32 {
        let off = self.pos();
        self.uleb((s.len() as u32) << 1 | 1).bytes(s.as_bytes()).u8(0);
        off
    }

    pub fn patch_u32(&mut self, at: u32, v: u32) {
        self.0[at as usize..at as usize + 4].copy_from_slice(&v.to_le_bytes());
    }
}

pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Offsets of the interesting items of [`synthetic`].
#[derive(Debug, Clone, Copy)]
pub struct Synthetic {
    pub class_index: u32,
    pub region_headers: u32,
    pub class_a: u32,
    pub class_b: u32,
    pub foreign_class: u32,
    pub str_hello: u32,
    pub str_world: u32,
    pub literal_array: u32,
    pub module_record: u32,
    pub scope_names: u32,
    pub code_main: u32,
    pub method_main: u32,
    pub method_build: u32,
    /// Region 1 methods: correct hint, out-of-range hint, wrong in-range hint.
    pub methods_b: [u32; 3],
}

pub const RECORD_A: &str = "&entry/src/main/ets/pages/Index&";
pub const RECORD_B: &str = "com.example.app/entry/ets/model/Util";

/// A two-region file, version 12.0.6.0 (literal array index present), with
/// a correct checksum. Region 0 holds record A, region 1 record B; both
/// name string `hello` but under different 16-bit ids.
pub fn synthetic() -> (Vec<u8>, Synthetic) {
    let mut s = Sink::default();
    s.bytes(&asc_abc::MAGIC).u32(0).bytes(&[12, 0, 6, 0]);
    s.bytes(&[0; 44]);
    assert_eq!(s.pos() as usize, asc_abc::HEADER_SIZE);

    let class_index = s.pos();
    s.bytes(&[0; 12]);
    let region_headers = s.pos();
    s.bytes(&[0; 80]);
    let lnp_index = s.pos();
    s.bytes(&[0; 4]);
    let literal_index = s.pos();
    s.bytes(&[0; 12]);
    let class_tables = [s.pos(), s.pos() + 20];
    s.bytes(&[0; 24]);
    let entity_tables = [s.pos(), s.pos() + 16];
    s.bytes(&[0; 32]);

    let foreign_off = s.pos();
    let foreign_class = s.string("L_ESTypeAnnotation;");
    let foreign_size = s.pos() - foreign_off;

    // Leaf data, outside both regions.
    let str_hello = s.string("hello");
    let str_world = s.string("world");
    let str_request = s.string("@ohos:hilog");
    let str_default = s.string("default");
    let str_local = s.string("hilog");
    let str_index = s.string("Index");
    let str_slot = s.string("SlotNumber");
    let names: Vec<u32> = [
        "moduleRecordIdx",
        "scopeNames",
        "isCommonjs",
        "pkgName@entry",
        "big",
        "func_main_0",
        "#~@0>#build",
        "#*#helper",
        "#*#helper^1",
        "#*#",
        "arg0",
    ]
    .iter()
    .map(|name| s.string(name))
    .collect();
    let wide_value = s.pos();
    s.bytes(&0x1122_3344_5566_7788u64.to_le_bytes());

    let literal_array = s.pos();
    s.u32(8);
    s.u8(0x02).u32(0x1d4b42);
    s.u8(0x05).u32(str_hello);
    s.u8(0x01).u8(1);
    s.u8(0x04).bytes(&1.5f64.to_le_bytes());
    let scope_names = s.pos();
    s.u32(2).u8(0x05).u32(str_index);
    let module_record = s.pos();
    s.u32(0).u32(1).u32(str_request);
    s.u32(1).u32(str_local).u32(str_default).u16(0);
    s.u32(1).u32(str_local).u16(0);
    s.u32(1).u32(str_index).u32(str_default);
    s.u32(1).u32(str_default).u32(str_default).u16(0);
    s.u32(1).u16(0);

    let line_program = s.pos();
    // advance_pc, advance_line, special (pc += 1, line += 1), set_column, special, end.
    s.bytes(&[0x01, 0x02, 0x0c + 15 + 5, 0x0b, 0x0c + 4, 0x00]);
    let debug_info = s.pos();
    s.uleb(10).uleb(1).uleb(names[10]);
    s.uleb(3).uleb(2).sleb(-1).uleb(7);
    s.uleb(0);

    let code_main = s.pos();
    // lda.str 0x0000; return
    s.uleb(1).uleb(3).uleb(4).uleb(0).bytes(&[0x3e, 0x00, 0x00, 0x64]);
    let code_build = s.pos();
    s.uleb(2).uleb(3).uleb(6).uleb(1).bytes(&[0x3e, 0x01, 0x00, 0x3e, 0x00, 0x64]);
    s.uleb(0).uleb(3).uleb(2);
    s.uleb(1).uleb(3).uleb(3);
    s.uleb(0).uleb(4).uleb(2);

    // Region 0: an annotation and record A.
    let region0_start = s.pos();
    let annotation = s.pos();
    s.u16(3).u16(1).u32(str_slot).u32(5).u8(b'7');
    let class_a = s.string(&format!("L{RECORD_A};"));
    s.u32(0).uleb(0x1).uleb(5).uleb(2);
    s.u8(0x02).u8(4).u8(0x00);
    s.u16(2).u16(0).u32(names[0]).uleb(0).u8(0x02).u32(module_record).u8(0x00);
    s.u16(2).u16(0).u32(names[1]).uleb(0).u8(0x02).u32(scope_names).u8(0x00);
    s.u16(2).u16(1).u32(names[2]).uleb(0).u8(0x01).sleb(0).u8(0x00);
    s.u16(2).u16(1).u32(names[3]).uleb(0).u8(0x01).sleb(0).u8(0x00);
    s.u16(2).u16(4).u32(names[4]).uleb(0x8).u8(0x02).u32(wide_value).u8(0x04).u32(annotation).u8(0x00);
    let method_main = s.pos();
    s.u16(2).u16(0).u32(names[5]).uleb(0x0108);
    s.u8(0x01).u32(code_main).u8(0x02).u8(4).u8(0x05).u32(debug_info).u8(0x06).u32(annotation).u8(0x00);
    let method_build = s.pos();
    s.u16(2).u16(0).u32(names[6]).uleb(0x0008).u8(0x01).u32(code_build).u8(0x00);
    let region0_end = s.pos();

    // Region 1: record B. The second method claims region 7, the third region 0.
    let class_b = s.string(&format!("L{RECORD_B};"));
    s.u32(0).uleb(0x1).uleb(0).uleb(3);
    s.u8(0x00);
    let mut methods_b = [0; 3];
    for (i, hint) in [1u32, 7, 0].into_iter().enumerate() {
        methods_b[i] = s.pos();
        s.u16(0).u16(0).u32(names[7 + i]).uleb(hint << 16 | 0x0208).u8(0x01).u32(code_main).u8(0x00);
    }
    let region1_end = s.pos();

    // Sorted by descriptor: `L&…` < `L_…` < `Lc…`.
    for (i, off) in [class_a, foreign_class, class_b].into_iter().enumerate() {
        s.patch_u32(class_index + 4 * i as u32, off);
    }
    s.patch_u32(lnp_index, line_program);
    for (i, off) in [literal_array, module_record, scope_names].into_iter().enumerate() {
        s.patch_u32(literal_index + 4 * i as u32, off);
    }
    // Class tables: u32, u1, the record itself, the annotation class, i64.
    for (i, entry) in [0x06, 0x00, class_a, foreign_class, 0x09].into_iter().enumerate() {
        s.patch_u32(class_tables[0] + 4 * i as u32, entry);
    }
    s.patch_u32(class_tables[1], class_b);
    // The same strings under different ids in each region.
    for (i, entry) in [str_hello, str_world, literal_array, method_build].into_iter().enumerate() {
        s.patch_u32(entity_tables[0] + 4 * i as u32, entry);
    }
    for (i, entry) in [str_world, methods_b[0], str_hello].into_iter().enumerate() {
        s.patch_u32(entity_tables[1] + 4 * i as u32, entry);
    }
    let regions = [
        [region0_start, region0_end, 5, class_tables[0], 4, entity_tables[0], 0, u32::MAX, u32::MAX, u32::MAX],
        [region0_end, region1_end, 1, class_tables[1], 3, entity_tables[1], u32::MAX, u32::MAX, u32::MAX, u32::MAX],
    ];
    for (i, word) in regions.iter().flatten().enumerate() {
        s.patch_u32(region_headers + 4 * i as u32, *word);
    }
    let file_size = s.pos();
    for (i, word) in
        [file_size, foreign_off, foreign_size, 3, class_index, 1, lnp_index, 3, literal_index, 2, region_headers].into_iter().enumerate()
    {
        s.patch_u32(16 + 4 * i as u32, word);
    }
    let checksum = adler32(&s.0[12..]);
    s.patch_u32(8, checksum);

    let offsets = Synthetic {
        class_index,
        region_headers,
        class_a,
        class_b,
        foreign_class,
        str_hello,
        str_world,
        literal_array,
        module_record,
        scope_names,
        code_main,
        method_main,
        method_build,
        methods_b,
    };
    (s.0, offsets)
}
