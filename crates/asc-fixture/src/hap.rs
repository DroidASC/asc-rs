//! In-memory HarmonyOS packages: a `.hap` (one module: `ets/*.abc`,
//! `module.json`, resources) and an `.app` (the bundle: haps plus
//! `pack.info`), and the `resources.index` of a module ([`ResourceTable`]);
//! [`unpack`] writes one out as the directory a user unzips it into.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use asc_abc::FunctionKind;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::abc::{
    AbcAnnotation, AbcBuilder, AbcCode, AbcField, AbcFieldValue, AbcFunction, AbcLiteral, AbcModule, AbcRecord, AbcType, Asm, Op,
    sample_program,
};

/// How a zip entry is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Stored,
    Deflated,
}

impl Compression {
    fn options(self) -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(match self {
            Compression::Stored => CompressionMethod::Stored,
            Compression::Deflated => CompressionMethod::Deflated,
        })
    }
}

/// `module.json` of the sample module: bundle `com.example.sample`, module
/// `entry`, an exported `EntryAbility` with a `sample://open` deep link and
/// the `ohos.permission.INTERNET` permission.
pub const SAMPLE_MODULE_JSON: &str = r#"{
  "app": {
    "bundleName": "com.example.sample",
    "vendor": "example",
    "versionCode": 1000000,
    "versionName": "1.0.0",
    "minAPIVersion": 50000012,
    "targetAPIVersion": 50000012
  },
  "module": {
    "name": "entry",
    "type": "entry",
    "mainElement": "EntryAbility",
    "deviceTypes": ["phone"],
    "pages": "$profile:main_pages",
    "abilities": [
      {
        "name": "EntryAbility",
        "srcEntry": "./ets/entryability/EntryAbility.ets",
        "exported": true,
        "skills": [
          {
            "entities": ["entity.system.home"],
            "actions": ["action.system.home"],
            "uris": [{ "scheme": "sample", "host": "open" }]
          }
        ]
      }
    ],
    "requestPermissions": [{ "name": "ohos.permission.INTERNET" }]
  }
}
"#;

/// `pack.info` matching [`SAMPLE_MODULE_JSON`].
pub const SAMPLE_PACK_INFO: &str = r#"{
  "summary": {
    "app": { "bundleName": "com.example.sample", "version": { "code": 1000000, "name": "1.0.0" } },
    "modules": [
      {
        "mainAbility": "EntryAbility",
        "deviceType": ["phone"],
        "abilities": [{ "name": "EntryAbility", "label": "$string:EntryAbility_label" }],
        "distro": { "moduleType": "entry", "deliveryWithInstall": true, "moduleName": "entry" }
      }
    ]
  },
  "packages": [{ "deviceType": ["phone"], "moduleType": "entry", "deliveryWithInstall": true, "name": "entry-default" }]
}
"#;

/// Type numbers of `resources.index`.
pub mod resource_type {
    pub const STRING: u32 = 9;
    pub const COLOR: u32 = 14;
    pub const MEDIA: u32 = 19;
    pub const PROFILE: u32 = 20;
}

/// Qualifiers as `resources.index` stores them: `(key, value)`.
pub mod qualifier {
    /// Language `zh`.
    pub const ZH: (u32, u32) = (0, 0x7a68);
    /// Region `CN`.
    pub const CN: (u32, u32) = (1, 0x434e);
    /// Color mode `dark`.
    pub const DARK: (u32, u32) = (6, 0);
}

#[derive(Debug, Clone)]
struct ResourceValue {
    id: u32,
    kind: u32,
    name: String,
    qualifiers: Vec<(u32, u32)>,
    value: String,
}

/// A `resources.index` under construction, written in the first layout
/// (`Restool <version>`): the qualifier sets, one id table per set, one
/// record per value.
///
/// ```
/// use asc_fixture::hap::{qualifier, resource_type, ResourceTable};
///
/// let index = ResourceTable::new()
///     .value(0x0100_0000, resource_type::STRING, "app_name", &[], "Shop")
///     .value(0x0100_0000, resource_type::STRING, "app_name", &[qualifier::ZH, qualifier::CN], "商店")
///     .build();
/// assert!(index.starts_with(b"Restool "));
/// ```
#[derive(Debug, Clone, Default)]
pub struct ResourceTable {
    values: Vec<ResourceValue>,
}

impl ResourceTable {
    /// Bytes of the version text that opens the file.
    const VERSION_LEN: usize = 128;

    pub fn new() -> ResourceTable {
        ResourceTable::default()
    }

    /// Add the value of resource `id` (`kind`: a number of
    /// [`resource_type`]) under `qualifiers` (none: the `base` value).
    /// Qualifier sets are written in the order they are first used.
    #[must_use]
    pub fn value(mut self, id: u32, kind: u32, name: &str, qualifiers: &[(u32, u32)], value: &str) -> ResourceTable {
        self.values.push(ResourceValue { id, kind, name: name.to_owned(), qualifiers: qualifiers.to_vec(), value: value.to_owned() });
        self
    }

    /// Write the index.
    pub fn build(&self) -> Vec<u8> {
        fn put32(out: &mut Vec<u8>, value: usize) {
            out.extend(u32::try_from(value).expect("a fixture index stays below 4 GiB").to_le_bytes());
        }
        fn put16(out: &mut Vec<u8>, value: usize) {
            out.extend(u16::try_from(value).expect("a fixture value stays below 64 KiB").to_le_bytes());
        }
        let mut sets: Vec<&[(u32, u32)]> = Vec::new();
        for value in &self.values {
            if !sets.contains(&value.qualifiers.as_slice()) {
                sets.push(&value.qualifiers);
            }
        }
        let members = |set: &[(u32, u32)]| -> Vec<&ResourceValue> { self.values.iter().filter(|value| value.qualifiers == set).collect() };
        // Header: version, file size, set count; then the sets, the id tables, the records.
        let header_len = Self::VERSION_LEN + 8;
        let keys_len: usize = sets.iter().map(|set| 12 + 8 * set.len()).sum();
        let tables_len: usize = sets.iter().map(|set| 8 + 8 * members(set).len()).sum();
        let tables_start = header_len + keys_len;
        let mut keys = Vec::new();
        let mut tables = Vec::new();
        let mut records = Vec::new();
        for set in &sets {
            keys.extend(b"KEYS");
            put32(&mut keys, tables_start + tables.len());
            put32(&mut keys, set.len());
            for &(key, value) in *set {
                keys.extend(key.to_le_bytes());
                keys.extend(value.to_le_bytes());
            }
            tables.extend(b"IDSS");
            put32(&mut tables, members(set).len());
            for value in members(set) {
                tables.extend(value.id.to_le_bytes());
                put32(&mut tables, tables_start + tables_len + records.len());
                // Value and name each end with a NUL their length counts.
                put32(&mut records, 8 + 2 + value.value.len() + 1 + 2 + value.name.len() + 1);
                records.extend(value.kind.to_le_bytes());
                records.extend(value.id.to_le_bytes());
                put16(&mut records, value.value.len() + 1);
                records.extend(value.value.as_bytes());
                records.push(0);
                put16(&mut records, value.name.len() + 1);
                records.extend(value.name.as_bytes());
                records.push(0);
            }
        }
        let mut out = b"Restool 5.0.1.011".to_vec();
        out.resize(Self::VERSION_LEN, 0);
        put32(&mut out, header_len + keys.len() + tables.len() + records.len());
        put32(&mut out, sets.len());
        out.extend(keys);
        out.extend(tables);
        out.extend(records);
        out
    }
}

/// Id of `string/EntryAbility_label` in [`sample_resources`].
pub const SAMPLE_LABEL_ID: u32 = 0x0100_0000;
/// Id of `color/brand` in [`sample_resources`].
pub const SAMPLE_BRAND_ID: u32 = 0x0100_0003;
/// `resources/base/profile/main_pages.json` of the sample module.
pub const SAMPLE_MAIN_PAGES: &str = "{\n  \"src\": [\"pages/Index\"]\n}\n";
/// Record of [`resource_program`] whose function `labels` builds resource objects.
pub const LABELS_PAGE: &str = "&entry/src/main/ets/pages/Labels&";

/// The resources of the sample module, what [`SAMPLE_MODULE_JSON`] and
/// [`SAMPLE_PACK_INFO`] refer to:
///
/// ```text
/// 0x01000000 string/EntryAbility_label [base] "Sample"   [zh_CN] "示例"
/// 0x01000001 profile/main_pages        [base] entry/resources/base/profile/main_pages.json
/// 0x01000002 color/accent              [base] "$color:16777219"   (a reference to color/brand)
/// 0x01000003 color/brand               [base] "#FF0000"   [dark] "#00FF00"
/// 0x01000004 media/icon                [base] entry/resources/base/media/icon.png
/// 0x01000005 string/api_host           [base] "https://example.com"
/// ```
///
/// The `zh_CN` qualifier set is the first of the file, ahead of `base`.
pub fn sample_resources() -> ResourceTable {
    use qualifier::{CN, DARK, ZH};
    use resource_type::{COLOR, MEDIA, PROFILE, STRING};
    ResourceTable::new()
        .value(SAMPLE_LABEL_ID, STRING, "EntryAbility_label", &[ZH, CN], "示例")
        .value(SAMPLE_LABEL_ID, STRING, "EntryAbility_label", &[], "Sample")
        .value(0x0100_0001, PROFILE, "main_pages", &[], "entry/resources/base/profile/main_pages.json")
        .value(0x0100_0002, COLOR, "accent", &[], "$color:16777219")
        .value(SAMPLE_BRAND_ID, COLOR, "brand", &[DARK], "#00FF00")
        .value(SAMPLE_BRAND_ID, COLOR, "brand", &[], "#FF0000")
        .value(0x0100_0004, MEDIA, "icon", &[], "entry/resources/base/media/icon.png")
        .value(0x0100_0005, STRING, "api_host", &[], "https://example.com")
}

/// [`sample_program`] plus the record [`LABELS_PAGE`], whose function
/// `#*#labels` creates the objects `$r(...)` compiles to, in this order:
/// `$r('app.string.EntryAbility_label')` (id [`SAMPLE_LABEL_ID`], type
/// 10003), `$r('app.color.brand')` ([`SAMPLE_BRAND_ID`], 10001), an object
/// with the label's id and the type of a color (names no resource),
/// `$rawfile('Home.html')` (id 0, type 30000) and a plain object.
pub fn resource_program() -> AbcBuilder {
    fn object(id: u32, kind: i32) -> [AbcLiteral; 10] {
        [
            AbcLiteral::str("id"),
            AbcLiteral::Integer(i32::try_from(id).expect("resource ids are below 2^31")),
            AbcLiteral::str("type"),
            AbcLiteral::Integer(kind),
            AbcLiteral::str("params"),
            AbcLiteral::Null,
            AbcLiteral::str("bundleName"),
            AbcLiteral::str("com.example.sample"),
            AbcLiteral::str("moduleName"),
            AbcLiteral::str("entry"),
        ]
    }
    let mut builder = sample_program();
    let objects = [
        builder.literal_array(object(SAMPLE_LABEL_ID, 10003)),
        builder.literal_array(object(SAMPLE_BRAND_ID, 10001)),
        builder.literal_array(object(SAMPLE_LABEL_ID, 10001)),
        builder.literal_array(object(0, 30000)),
        builder.literal_array([AbcLiteral::str("id"), AbcLiteral::str("x")]),
    ];
    let mut labels = Asm::new();
    for object in objects {
        labels.op("createobjectwithbuffer", [0.into(), object.into()]).op("sta", [0.into()]);
    }
    labels.op("returnundefined", []);
    let function =
        AbcFunction::new("#*#labels", AbcCode::new(1, 3, labels)).kind(FunctionKind::FUNCTION).annotation(AbcAnnotation::slot_number(5));
    builder.record(AbcRecord::ets_module(LABELS_PAGE, "entry", &[], AbcModule::new()).function(function));
    builder
}

/// Record of [`routed_program`] that a route of [`SAMPLE_ROUTER_MAP`] names.
pub const DETAIL_PAGE: &str = "&entry/src/main/ets/pages/Detail&";
/// Record of [`routed_program`] that holds the long strings.
pub const LONG_PAGE: &str = "&entry/src/main/ets/pages/Long&";
/// Record of [`library_program`]: the page of a route in another package.
pub const SHARED_PAGE: &str = "&@sample/lib/src/main/ets/pages/Shared&1.0.0";
/// What the long strings of [`routed_program`] hold far behind their start.
pub const LONG_MARKER: &str = "https://example.com/far";
/// Bytes of filler ahead of [`LONG_MARKER`] in each long string.
pub const LONG_FILLER_BYTES: usize = 3000;

/// `module.json` of the routed module: [`SAMPLE_MODULE_JSON`] with a route
/// table (`routerMap`), which no resource index lists.
pub fn routed_module_json() -> String {
    SAMPLE_MODULE_JSON
        .replace("\"pages\": \"$profile:main_pages\",", "\"pages\": \"$profile:main_pages\",\n    \"routerMap\": \"$profile:router_map\",")
}

/// `resources/base/profile/router_map.json` of the routed module, on one
/// line as the build writes it: a route whose page is a record of the
/// module ([`DETAIL_PAGE`]), one in another package ([`SHARED_PAGE`], named
/// by its `ohmurl`), one spelled by its source file alone (the sample's
/// index page) and one whose page no code has.
pub const SAMPLE_ROUTER_MAP: &str = concat!(
    r#"{"routerMap":[{"buildFunction":"DetailBuilder","name":"detail","pageSourceFile":"src/main/ets/pages/Detail.ets","#,
    r#""ohmurl":"@normalized:N&&&entry/src/main/ets/pages/Detail&","customData":{"title":"Detail"}},"#,
    r#"{"buildFunction":"SharedBuilder","name":"lib/shared","pageSourceFile":"src/main/ets/pages/Shared.ets","#,
    r#""packageName":"@sample/lib","ohmurl":"@normalized:N&lib&&@sample/lib/src/main/ets/pages/Shared&1.0.0"},"#,
    r#"{"buildFunction":"IndexBuilder","name":"index","pageSourceFile":"src/main/ets/pages/Index.ets"},"#,
    r#"{"buildFunction":"GoneBuilder","name":"gone","pageSourceFile":"src/main/ets/pages/Gone.ets"}]}"#
);

/// A string of [`LONG_FILLER_BYTES`] of `filler`, then [`LONG_MARKER`] and `tail`.
fn long_text(filler: &str, tail: &str) -> String {
    format!("{}{LONG_MARKER}{tail}", filler.repeat(LONG_FILLER_BYTES / filler.len()))
}

/// [`sample_program`] plus two records: [`DETAIL_PAGE`], with the builder
/// function `#*#DetailBuilder`, and [`LONG_PAGE`], whose strings are longer
/// than a row shows, each with [`LONG_MARKER`] behind [`LONG_FILLER_BYTES`]
/// of filler: the operand of an `lda.str` in `#*#long`, an item of the
/// literal array that function creates, and the record's `jsonFileContent`.
pub fn routed_program() -> AbcBuilder {
    let function = |name: &str, asm: Asm| {
        AbcFunction::new(name, AbcCode::new(1, 3, asm)).kind(FunctionKind::FUNCTION).annotation(AbcAnnotation::slot_number(1))
    };
    let mut builder = sample_program();
    let mut detail = Asm::new();
    detail.op("lda.str", [Op::str("detail")]).op("return", []);
    builder.record(AbcRecord::ets_module(DETAIL_PAGE, "entry", &[], AbcModule::new()).function(function("#*#DetailBuilder", detail)));

    let items = builder.literal_array([AbcLiteral::str("short"), AbcLiteral::str(&long_text("b", "/item"))]);
    let mut long = Asm::new();
    long.op("lda.str", [Op::str(&long_text("a", "/operand"))]).op("sta", [0.into()]);
    long.op("createarraywithbuffer", [0.into(), items.into()]).op("return", []);
    let content = AbcFieldValue::String(format!("{{\"text\":\"{}\"}}", long_text("c", "/field")));
    builder.record(
        AbcRecord::ets_module(LONG_PAGE, "entry", &[], AbcModule::new())
            .field(AbcField::new("jsonFileContent", AbcType::U32, content))
            .function(function("#*#long", long)),
    );
    builder
}

/// The code of a second package: the record [`SHARED_PAGE`] with the
/// builder function `#*#SharedBuilder`.
pub fn library_program() -> AbcBuilder {
    let mut shared = Asm::new();
    shared.op("lda.str", [Op::str("shared")]).op("return", []);
    let function = AbcFunction::new("#*#SharedBuilder", AbcCode::new(1, 3, shared))
        .kind(FunctionKind::FUNCTION)
        .annotation(AbcAnnotation::slot_number(1));
    let mut builder = AbcBuilder::new();
    builder.record(AbcRecord::annotation_interface("_ESSlotNumberAnnotation"));
    builder.record(AbcRecord::ets_module(SHARED_PAGE, "@sample/lib", &[], AbcModule::new()).function(function));
    builder
}

/// `module.json` of the library package: a shared module `lib` of the
/// sample bundle, without components.
pub const LIBRARY_MODULE_JSON: &str = r#"{
  "app": { "bundleName": "com.example.sample", "versionCode": 1000000, "versionName": "1.0.0" },
  "module": { "name": "lib", "type": "shared", "packageName": "@sample/lib", "deviceTypes": ["phone"] }
}
"#;

/// The routed module as a `.hap`: [`routed_program`], [`routed_module_json`],
/// the resources of the sample and its page list, [`SAMPLE_ROUTER_MAP`]
/// where the build puts a route table, and [`SAMPLE_PACK_INFO`].
pub fn make_routed_hap() -> Vec<u8> {
    Hap::new()
        .modules_abc(&routed_program().build().bytes)
        .module_json(&routed_module_json())
        .resource_index(&sample_resources())
        .entry("resources/base/profile/main_pages.json", SAMPLE_MAIN_PAGES.as_bytes(), Compression::Deflated)
        .entry("resources/base/profile/router_map.json", SAMPLE_ROUTER_MAP.as_bytes(), Compression::Deflated)
        .pack_info(SAMPLE_PACK_INFO)
        .build()
}

/// The library package as an `.hsp`: [`library_program`],
/// [`LIBRARY_MODULE_JSON`] and [`SAMPLE_PACK_INFO`], the same bytes the
/// routed module carries (one build writes one `pack.info` into all of its
/// packages).
pub fn make_library_hsp() -> Vec<u8> {
    Hap::new().modules_abc(&library_program().build().bytes).module_json(LIBRARY_MODULE_JSON).pack_info(SAMPLE_PACK_INFO).build()
}

/// A `.hap` under construction. Entries are written in the order they are
/// added.
///
/// ```
/// use asc_fixture::hap::Hap;
///
/// let hap = Hap::new().modules_abc(&asc_fixture::abc::make_abc()).abc("widgets", &[]).module_json("{}").build();
/// assert_eq!(&hap[..2], b"PK");
/// ```
#[derive(Debug, Clone)]
pub struct Hap {
    entries: Vec<HapEntry>,
    abc_compression: Compression,
}

#[derive(Debug, Clone)]
struct HapEntry {
    name: String,
    data: Vec<u8>,
    compression: Compression,
}

impl Default for Hap {
    fn default() -> Hap {
        Hap::new()
    }
}

impl Hap {
    /// An empty archive. ABC entries are stored uncompressed, as in real
    /// haps, unless [`Hap::deflate_abc`] is called before adding them.
    pub fn new() -> Hap {
        Hap { entries: Vec::new(), abc_compression: Compression::Stored }
    }

    /// Compress the ABC entries added from here on.
    #[must_use]
    pub fn deflate_abc(mut self) -> Hap {
        self.abc_compression = Compression::Deflated;
        self
    }

    /// Add `ets/modules.abc`.
    #[must_use]
    pub fn modules_abc(self, abc: &[u8]) -> Hap {
        self.abc("modules", abc)
    }

    /// Add `ets/<name>.abc`.
    #[must_use]
    pub fn abc(self, name: &str, abc: &[u8]) -> Hap {
        let compression = self.abc_compression;
        self.entry(&format!("ets/{name}.abc"), abc, compression)
    }

    /// Add `module.json` (stored, as in real haps).
    #[must_use]
    pub fn module_json(self, json: &str) -> Hap {
        self.entry("module.json", json.as_bytes(), Compression::Stored)
    }

    /// Add `resources.index` (stored, as in real haps).
    #[must_use]
    pub fn resource_index(self, table: &ResourceTable) -> Hap {
        self.entry("resources.index", &table.build(), Compression::Stored)
    }

    /// Add `ets/sourceMaps.map`, the source maps of a debug build.
    #[must_use]
    pub fn source_maps(self, json: &str) -> Hap {
        self.entry("ets/sourceMaps.map", json.as_bytes(), Compression::Deflated)
    }

    /// Add `pack.info`.
    #[must_use]
    pub fn pack_info(self, json: &str) -> Hap {
        self.entry("pack.info", json.as_bytes(), Compression::Deflated)
    }

    /// Add any entry.
    #[must_use]
    pub fn entry(mut self, name: &str, data: &[u8], compression: Compression) -> Hap {
        self.entries.push(HapEntry { name: name.to_owned(), data: data.to_vec(), compression });
        self
    }

    /// Write the archive.
    pub fn build(&self) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for entry in &self.entries {
            zip.start_file(entry.name.as_str(), entry.compression.options()).expect("zip entry starts");
            zip.write_all(&entry.data).expect("writing to memory cannot fail");
        }
        zip.finish().expect("zip archive finishes").into_inner()
    }
}

/// A `.hap` with `modules_abc` as `ets/modules.abc` (stored),
/// [`SAMPLE_MODULE_JSON`], [`sample_resources`] as `resources.index`
/// (stored) with the two files it names ([`SAMPLE_MAIN_PAGES`], deflated,
/// and an icon that is not text) and [`SAMPLE_PACK_INFO`]. Use [`Hap`] for
/// anything else.
pub fn make_hap(modules_abc: &[u8]) -> Vec<u8> {
    Hap::new()
        .modules_abc(modules_abc)
        .module_json(SAMPLE_MODULE_JSON)
        .resource_index(&sample_resources())
        .entry("resources/base/profile/main_pages.json", SAMPLE_MAIN_PAGES.as_bytes(), Compression::Deflated)
        .entry("resources/base/media/icon.png", b"\x89PNG\r\n\x1a\n", Compression::Stored)
        .pack_info(SAMPLE_PACK_INFO)
        .build()
}

/// `ets/sourceMaps.map` for the sample program of [`crate::abc`], as a
/// debug build writes it: one source map per compiled module. Line 12 of
/// the compiled page, where the debug info puts `Index.build`, comes from
/// line 4 of `Index.ets`; the map of the ability ends before line 6, where
/// its `onCreate` is, as it does for code the build appends.
pub const SAMPLE_SOURCE_MAPS: &str = r#"{
  "entry|entry|1.0.0|src/main/ets/pages/Index.ts": {
    "version": 3,
    "file": "Index.ets",
    "sourceRoot": "",
    "sources": ["entry/src/main/ets/pages/Index.ets"],
    "names": [],
    "mappings": ";;;;;;;;;;;;AAGA;AACA",
    "entry-package-info": "entry|1.0.0"
  },
  "entry|entry|1.0.0|src/main/ets/entryability/EntryAbility.ts": {
    "version": 3,
    "file": "EntryAbility.ets",
    "sourceRoot": "",
    "sources": ["entry/src/main/ets/entryability/EntryAbility.ets"],
    "names": [],
    "mappings": "AAAA;AACA",
    "entry-package-info": "entry|1.0.0"
  }
}
"#;

/// [`make_hap`] of a debug build: with [`SAMPLE_SOURCE_MAPS`] (deflated).
pub fn make_debug_hap(modules_abc: &[u8]) -> Vec<u8> {
    Hap::new()
        .modules_abc(modules_abc)
        .source_maps(SAMPLE_SOURCE_MAPS)
        .module_json(SAMPLE_MODULE_JSON)
        .resource_index(&sample_resources())
        .entry("resources/base/profile/main_pages.json", SAMPLE_MAIN_PAGES.as_bytes(), Compression::Deflated)
        .pack_info(SAMPLE_PACK_INFO)
        .build()
}

/// Unpack `archive` (a zip, say a `.hap`) into `dir`, every entry at its
/// path below it, the way a user unzips a package to look inside.
///
/// # Panics
/// When `archive` is not a zip, an entry's name leaves `dir`, or a file
/// cannot be written.
pub fn unpack(archive: &[u8], dir: &Path) {
    let mut zip = ZipArchive::new(Cursor::new(archive)).expect("the archive is a zip");
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).expect("zip entry reads");
        let path = dir.join(entry.enclosed_name().expect("entry name stays inside the directory"));
        if entry.is_dir() {
            fs::create_dir_all(&path).expect("directory is created");
            continue;
        }
        fs::create_dir_all(path.parent().expect("a file has a directory")).expect("directory is created");
        let mut data = Vec::new();
        entry.read_to_end(&mut data).expect("zip entry inflates");
        fs::write(&path, data).expect("file is written");
    }
}

/// An `.app`: the `(name, bytes)` haps, each stored as `inner` says (real
/// bundles have both stored and deflated inner haps), plus
/// [`SAMPLE_PACK_INFO`] as `pack.info`.
pub fn make_app(haps: &[(&str, &[u8])], inner: Compression) -> Vec<u8> {
    let app = haps.iter().fold(Hap::new(), |app, (name, hap)| app.entry(name, hap, inner));
    app.pack_info(SAMPLE_PACK_INFO).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(archive: &[u8]) -> Vec<(String, CompressionMethod, Vec<u8>)> {
        let mut zip = ZipArchive::new(Cursor::new(archive)).unwrap();
        (0..zip.len())
            .map(|index| {
                let mut entry = zip.by_index(index).unwrap();
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                (entry.name().to_owned(), entry.compression(), data)
            })
            .collect()
    }

    #[test]
    fn hap_stores_abc_and_module_json() {
        let abc = crate::abc::make_abc();
        let hap = make_hap(&abc);
        let listed = entries(&hap);
        let names: Vec<&str> = listed.iter().map(|(name, ..)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "ets/modules.abc",
                "module.json",
                "resources.index",
                "resources/base/profile/main_pages.json",
                "resources/base/media/icon.png",
                "pack.info"
            ]
        );
        assert_eq!(listed[0], ("ets/modules.abc".to_owned(), CompressionMethod::Stored, abc.clone()));
        assert_eq!((listed[1].1, listed[1].2.as_slice()), (CompressionMethod::Stored, SAMPLE_MODULE_JSON.as_bytes()));
        assert_eq!((listed[2].1, &listed[2].2), (CompressionMethod::Stored, &sample_resources().build()));
        assert_eq!(listed[5].1, CompressionMethod::Deflated);
        // Stored means the ABC is in the archive byte for byte: readers can slice it out of a mapping.
        assert!(hap.windows(abc.len()).any(|window| window == abc));

        let custom = Hap::new().deflate_abc().modules_abc(&abc).abc("widgets", b"second").entry(
            "libs/arm64-v8a/libentry.so",
            b"\x7fELF",
            Compression::Deflated,
        );
        let listed = entries(&custom.build());
        assert_eq!(listed[0].1, CompressionMethod::Deflated);
        assert_eq!((listed[1].0.as_str(), listed[1].2.as_slice()), ("ets/widgets.abc", &b"second"[..]));
        assert_eq!(listed[2].0, "libs/arm64-v8a/libentry.so");
    }

    #[test]
    fn resource_index_has_the_first_layout() {
        let index = ResourceTable::new()
            .value(0x0100_0000, resource_type::STRING, "app_name", &[], "Shop")
            .value(0x0100_0001, resource_type::COLOR, "accent", &[qualifier::DARK], "#000000")
            .value(0x0100_0000, resource_type::STRING, "app_name", &[qualifier::ZH, qualifier::CN], "商店")
            .build();
        let word = |at: usize| u32::from_le_bytes(index[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(&index[..17], b"Restool 5.0.1.011");
        assert!(index[17..128].iter().all(|&b| b == 0));
        assert_eq!((word(128), word(132)), (index.len(), 3), "file size, qualifier sets");
        // The first set is `base`: no qualifiers, its id table right behind the three sets.
        assert_eq!(&index[136..140], b"KEYS");
        let table = word(140);
        assert_eq!((word(144), table), (0, 136 + 12 + (12 + 8) + (12 + 16)));
        assert_eq!((&index[table..table + 4], word(table + 4), word(table + 8)), (&b"IDSS"[..], 1, 0x0100_0000));
        // Its one record: size, type, id, the value and the name with their NULs.
        let record = word(table + 12);
        assert_eq!((word(record), word(record + 4), word(record + 8)), (8 + 2 + 5 + 2 + 9, 9, 0x0100_0000));
        assert_eq!(&index[record + 12..record + 12 + 7], b"\x05\0Shop\0");
        assert_eq!(&index[record + 19..record + 19 + 11], b"\x09\0app_name\0");
        assert_eq!(resource_program().build().bytes[..8], asc_abc::MAGIC);
    }

    #[test]
    fn the_routed_module_names_its_route_table_and_long_strings() {
        let manifest = routed_module_json();
        assert!(manifest.contains("\"routerMap\": \"$profile:router_map\"") && manifest.len() > SAMPLE_MODULE_JSON.len());
        assert_eq!(SAMPLE_ROUTER_MAP.lines().count(), 1);
        assert_eq!(SAMPLE_ROUTER_MAP.matches("\"buildFunction\"").count(), 4);
        let long = long_text("a", "/operand");
        assert_eq!(long.find(LONG_MARKER), Some(LONG_FILLER_BYTES));
        let names: Vec<String> = entries(&make_routed_hap()).into_iter().map(|(name, ..)| name).collect();
        assert!(names.contains(&"resources/base/profile/router_map.json".to_owned()), "{names:?}");
        assert_eq!(routed_program().build().bytes[..8], asc_abc::MAGIC);
        assert_eq!(entries(&make_library_hsp()).len(), 3);
    }

    /// [`unpack`] is exercised where a directory may be made: by the tests of the engine.
    #[test]
    fn a_debug_hap_packs_its_source_maps() {
        let listed = entries(&make_debug_hap(&crate::abc::make_abc()));
        assert_eq!((listed[1].0.as_str(), listed[1].1), ("ets/sourceMaps.map", CompressionMethod::Deflated));
        assert_eq!(listed[1].2, SAMPLE_SOURCE_MAPS.as_bytes());
        assert!(listed.iter().any(|(name, ..)| name == "module.json") && listed.iter().any(|(name, ..)| name == "resources.index"));
    }

    #[test]
    fn app_nests_haps_stored_or_deflated() {
        let abc = crate::abc::make_abc();
        let hap = make_hap(&abc);
        for (inner, method) in [(Compression::Stored, CompressionMethod::Stored), (Compression::Deflated, CompressionMethod::Deflated)] {
            let app = make_app(&[("entry-default.hap", &hap), ("feature-default.hap", &hap)], inner);
            let listed = entries(&app);
            let names: Vec<&str> = listed.iter().map(|(name, ..)| name.as_str()).collect();
            assert_eq!(names, ["entry-default.hap", "feature-default.hap", "pack.info"]);
            assert_eq!((listed[0].1, &listed[0].2), (method, &hap));
            assert_eq!(entries(&listed[1].2)[0].2, abc);
            assert_eq!(app.windows(hap.len()).any(|window| window == hap), inner == Compression::Stored);
        }
    }
}
