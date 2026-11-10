//! `ets/sourceMaps.map`: the source maps a debug build packs next to its code.
//!
//! The file is one JSON object with a member per compiled module. The key
//! names the module, `entry|@scope/lib|1.0.0|src/main/ets/pages/Index.ts`
//! (the package that was built, the package the module is part of, its
//! version, the path of the compiled file inside it; older tools write the
//! path alone, `entry/src/main/ets/pages/Index.ts`). The value is a source
//! map (version 3) from that compiled file to the source it was made from:
//!
//! ```json
//! {"version": 3, "file": "Index.ets", "sources": ["entry/src/main/ets/pages/Index.ets"],
//!  "names": [], "mappings": "AAAA;AACA,…", "entry-package-info": "entry|1.0.0"}
//! ```
//!
//! The line numbers of the debug info in the `.abc` are lines of the
//! compiled file, counted from 0: the file the build wrote after turning
//! `struct` components into classes, which has lines no source line stands
//! behind. [`ModuleMap::source_line`] takes such a line to the source.
//!
//! The file of a large application is tens of megabytes, almost all of it
//! `mappings`. [`SourceMaps::index`] walks it once and keeps only where the
//! value of each module is; [`SourceMaps::module`] parses the one it is
//! asked for.

use std::collections::HashMap;
use std::ops::Range;

use serde_json::Value;

/// Why a source map table could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SourceMapError {
    #[error("not a JSON object of source maps: {expected} expected at byte {at}")]
    Malformed {
        /// What the grammar wants there.
        expected: &'static str,
        at: usize,
    },
    #[error("the source map of {key} does not read: {reason}")]
    Module { key: String, reason: String },
}

/// One member of the table: its key and where its value lies in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    key: String,
    /// `None` for a key that names no version (the older spelling).
    version: Option<String>,
    value: Range<usize>,
}

/// The modules of an `ets/sourceMaps.map`, by the record compiled from each.
/// It holds no part of the file: the bytes are passed again to read a module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMaps {
    slots: Vec<Slot>,
    /// `pkg/path/of/Module` (no extension) to the slots of that name, one
    /// per version of the package.
    by_name: HashMap<String, Vec<usize>>,
}

impl SourceMaps {
    /// Find the members of the table in `bytes`. Their values are skipped,
    /// not parsed.
    ///
    /// # Errors
    /// [`SourceMapError::Malformed`] when `bytes` is not a JSON object, or
    /// ends inside one.
    pub fn index(bytes: &[u8]) -> Result<SourceMaps, SourceMapError> {
        let mut maps = SourceMaps::default();
        let mut scan = Scanner { bytes, at: 0 };
        scan.expect(b'{', "'{'")?;
        if scan.peek() == Some(b'}') {
            return Ok(maps);
        }
        loop {
            let key = scan.string()?;
            scan.expect(b':', "':'")?;
            let value = scan.value()?;
            // A key that is not text names no module anyone asks for.
            if let Ok(key) = serde_json::from_slice::<String>(&bytes[key]) {
                maps.push(key, value);
            }
            match scan.peek() {
                Some(b',') => scan.at += 1,
                Some(b'}') => return Ok(maps),
                _ => return Err(scan.malformed("',' or '}'")),
            }
        }
    }

    fn push(&mut self, key: String, value: Range<usize>) {
        let (name, version) = ModuleKey::parse(&key).record_stem();
        let slot = self.slots.len();
        // Records of the older naming leave `src/main` out: `bundle/entry/ets/pages/Index`.
        if let Some((package, path)) = name.split_once("/src/main/") {
            self.by_name.entry(format!("{package}/{path}")).or_default().push(slot);
        }
        self.by_name.entry(name).or_default().push(slot);
        self.slots.push(Slot { key, version, value });
    }

    /// How many modules the table has.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The keys of the table, in file order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.slots.iter().map(|slot| slot.key.as_str())
    }

    fn slot_of(&self, record: &str) -> Option<&Slot> {
        let (name, version) = match record.strip_prefix('&') {
            // `&pkg/path&version`, the version empty for the package that was built.
            Some(rest) => {
                let (name, version) = rest.split_once('&')?;
                (name, Some(version).filter(|version| !version.is_empty()))
            }
            // `bundle/module/ets/path`: the table does not know the bundle.
            None => (record.split_once('/').map_or(record, |(_, rest)| rest), None),
        };
        let slots = self.by_name.get(name)?;
        let mut slots = slots.iter().map(|&slot| &self.slots[slot]);
        match version {
            Some(version) => slots.find(|slot| slot.version.as_deref().is_none_or(|own| own == version)),
            None => slots.next(),
        }
    }

    /// The source map of the module record `record` was compiled from
    /// (`&entry/src/main/ets/pages/Index&`, `&@scope/lib/Index&1.0.0`,
    /// `com.example.app/entry/ets/pages/Index`), read from `bytes`, the file
    /// this was indexed from. `None` when the table has no such module.
    ///
    /// # Errors
    /// [`SourceMapError::Module`] when the value is not a source map.
    pub fn module(&self, bytes: &[u8], record: &str) -> Option<Result<ModuleMap, SourceMapError>> {
        let slot = self.slot_of(record)?;
        let failed = |reason: String| SourceMapError::Module { key: slot.key.clone(), reason };
        let value = bytes.get(slot.value.clone()).ok_or_else(|| failed("the file is shorter than it was".to_owned()));
        Some(value.and_then(|value| ModuleMap::parse(value).map_err(failed)))
    }
}

/// The parts of a key of the table.
struct ModuleKey<'k> {
    /// `(package, version)` of the package the module is part of.
    package: Option<(&'k str, &'k str)>,
    /// The compiled file, inside the package (or from the project root in
    /// the older spelling).
    path: &'k str,
}

impl<'k> ModuleKey<'k> {
    fn parse(key: &'k str) -> ModuleKey<'k> {
        let mut parts = key.splitn(4, '|');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(_built), Some(package), Some(version), Some(path)) => ModuleKey { package: Some((package, version)), path },
            _ => ModuleKey { package: None, path: key },
        }
    }

    /// What record names say of the module: `package/path` without the
    /// extension of the file, and the version.
    fn record_stem(&self) -> (String, Option<String>) {
        let file = self.path.rsplit('/').next().unwrap_or(self.path);
        let stem = match file.rsplit_once('.') {
            Some((stem, _)) if !stem.is_empty() => &self.path[..self.path.len() - (file.len() - stem.len())],
            _ => self.path,
        };
        match self.package {
            Some((package, version)) => (format!("{package}/{stem}"), Some(version.to_owned())),
            None => (stem.to_owned(), None),
        }
    }
}

/// A walk over JSON text that finds where values end without building them.
struct Scanner<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl Scanner<'_> {
    fn malformed(&self, expected: &'static str) -> SourceMapError {
        SourceMapError::Malformed { expected, at: self.at }
    }

    /// The next byte that is not white space, without consuming it.
    fn peek(&mut self) -> Option<u8> {
        while let Some(&byte) = self.bytes.get(self.at) {
            if !byte.is_ascii_whitespace() {
                return Some(byte);
            }
            self.at += 1;
        }
        None
    }

    fn expect(&mut self, byte: u8, expected: &'static str) -> Result<(), SourceMapError> {
        if self.peek() != Some(byte) {
            return Err(self.malformed(expected));
        }
        self.at += 1;
        Ok(())
    }

    /// A string, quotes included.
    fn string(&mut self) -> Result<Range<usize>, SourceMapError> {
        let start = self.at;
        self.expect(b'"', "a string")?;
        while let Some(&byte) = self.bytes.get(self.at) {
            self.at += 1;
            match byte {
                b'"' => return Ok(start..self.at),
                // Whatever is escaped, it is not the closing quote.
                b'\\' => self.at += 1,
                _ => {}
            }
        }
        Err(self.malformed("'\"'"))
    }

    /// Any value: only its brackets and strings are looked at.
    fn value(&mut self) -> Result<Range<usize>, SourceMapError> {
        let Some(first) = self.peek() else { return Err(self.malformed("a value")) };
        let start = self.at;
        if first == b'"' {
            return self.string();
        }
        if first != b'{' && first != b'[' {
            // A number or a word: up to what cannot be part of one.
            let rest = &self.bytes[start..];
            let len = rest.iter().position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']' | b'"' | b':'));
            self.at += len.unwrap_or(rest.len());
            return if self.at == start { Err(self.malformed("a value")) } else { Ok(start..self.at) };
        }
        let mut depth = 0usize;
        while let Some(&byte) = self.bytes.get(self.at) {
            match byte {
                b'"' => {
                    self.string()?;
                    continue;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        self.at += 1;
                        return Ok(start..self.at);
                    }
                }
                _ => {}
            }
            self.at += 1;
        }
        Err(self.malformed("']' or '}'"))
    }
}

/// The source map of one module: which source line each line of the
/// compiled file comes from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleMap {
    /// The source files, as the build names them: from the project root
    /// (`entry/src/main/ets/pages/Index.ets`,
    /// `oh_modules/.ohpm/lib@1.0.0/oh_modules/lib/index.ts`).
    pub sources: Vec<String>,
    /// How many identifier names the map carries (`names`): none in the
    /// maps the build tools are known to write.
    pub names: usize,
    /// Per line of the compiled file, from 0: the line of `sources[0]`,
    /// from 1, its first mapped position comes from.
    lines: Vec<Option<u32>>,
    /// Whether `mappings` stopped at something that is not a mapping; the
    /// lines before it stand.
    pub damaged: bool,
}

impl ModuleMap {
    fn parse(value: &[u8]) -> Result<ModuleMap, String> {
        let value: Value = serde_json::from_slice(value).map_err(|err| err.to_string())?;
        let Some(mappings) = value.get("mappings").and_then(Value::as_str) else {
            return Err("no \"mappings\" string".to_owned());
        };
        let sources = value.get("sources").and_then(Value::as_array).map_or_else(Vec::new, |sources| {
            // A source that is not a string keeps its place: mappings name sources by index.
            sources.iter().map(|source| source.as_str().unwrap_or_default().to_owned()).collect()
        });
        let names = value.get("names").and_then(Value::as_array).map_or(0, Vec::len);
        let (lines, damaged) = decode_lines(mappings);
        Ok(ModuleMap { sources, names, lines, damaged })
    }

    /// The source file the lines of [`ModuleMap::source_line`] are lines of.
    pub fn source(&self) -> Option<&str> {
        self.sources.first().map(String::as_str).filter(|source| !source.is_empty())
    }

    /// The line of [`ModuleMap::source`], counted from 1, that line
    /// `compiled` of the compiled file (counted from 0, as the debug info
    /// of the code counts) was made from; `None` for a line the build
    /// added, and for one past the end of the map.
    pub fn source_line(&self, compiled: u32) -> Option<u32> {
        self.lines.get(usize::try_from(compiled).ok()?).copied().flatten()
    }

    /// [`ModuleMap::source_line`] of every line of the compiled file.
    pub fn source_lines(&self) -> &[Option<u32>] {
        &self.lines
    }
}

/// The value of a base 64 digit of a VLQ.
fn digit(byte: u8) -> Option<i64> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(i64::from(value))
}

/// The fields of one segment (`AAgBC`): up to five numbers, each relative.
/// `None` for text that is no segment.
fn segment(text: &[u8]) -> Option<([i64; 5], usize)> {
    const CONTINUES: i64 = 32;
    let mut fields = [0i64; 5];
    let mut count = 0;
    let (mut value, mut shift) = (0i64, 0u32);
    for &byte in text {
        let digit = digit(byte)?;
        // A field of a real map is a line or a column: it fits many times over.
        if shift > 40 || count == fields.len() {
            return None;
        }
        value |= (digit & (CONTINUES - 1)) << shift;
        if digit & CONTINUES != 0 {
            shift += 5;
            continue;
        }
        fields[count] = if value & 1 == 1 { -(value >> 1) } else { value >> 1 };
        count += 1;
        (value, shift) = (0, 0);
    }
    (shift == 0).then_some((fields, count))
}

/// The source line of the first position of each compiled line that comes
/// from the first source file, and whether the text broke off.
fn decode_lines(mappings: &str) -> (Vec<Option<u32>>, bool) {
    let mut lines = Vec::new();
    // Both run on from segment to segment, across lines.
    let (mut source, mut source_line) = (0i64, 0i64);
    for line in mappings.as_bytes().split(|&byte| byte == b';') {
        let mut first = None;
        for text in line.split(|&byte| byte == b',').filter(|text| !text.is_empty()) {
            let Some((fields, count)) = segment(text) else { return (lines, true) };
            // One field is a column nothing stands behind.
            if count < 4 {
                continue;
            }
            source = source.saturating_add(fields[1]);
            source_line = source_line.saturating_add(fields[2]);
            if first.is_none() && source == 0 {
                first = u32::try_from(source_line).ok().and_then(|line| line.checked_add(1));
            }
        }
        lines.push(first);
    }
    (lines, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = r#"{
      "entry|entry|1.0.0|src/main/ets/pages/Index.ts": {
        "version": 3, "file": "Index.ets", "sourceRoot": "",
        "sources": ["entry/src/main/ets/pages/Index.ets"], "names": [],
        "mappings": ";;AAAA;AACA,IAAI;;AAGJ", "entry-package-info": "entry|1.0.0"},
      "entry|@scope/lib|2.0.0|src/main/js/lib.js": {
        "version": 3, "sources": ["oh_modules/@scope/lib/src/main/js/lib.js"], "names": ["a\"}"], "mappings": "AAEA"},
      "entry|@scope/lib|3.1.0|src/main/js/lib.js": {"sources": [], "mappings": ""},
      "entry|entry|1.0.0|src/main/ets/broken.ts": {"mappings": 7},
      "other/src/main/ets/Old.ts": {"sources": ["other/src/main/ets/Old.ets"], "mappings": "AAAA;A*"}
    }"#;

    #[test]
    fn modules_are_found_by_record() {
        let maps = SourceMaps::index(TABLE.as_bytes()).unwrap();
        assert_eq!(maps.len(), 5);
        assert_eq!(maps.keys().next(), Some("entry|entry|1.0.0|src/main/ets/pages/Index.ts"));
        let module = |record: &str| maps.module(TABLE.as_bytes(), record);

        let index = module("&entry/src/main/ets/pages/Index&").unwrap().unwrap();
        assert_eq!(index.source(), Some("entry/src/main/ets/pages/Index.ets"));
        // Two lines the build added, then source lines 1 and 2, a gap, line 5.
        assert_eq!(index.source_lines(), [None, None, Some(1), Some(2), None, Some(5)]);
        assert_eq!((index.source_line(3), index.source_line(4), index.source_line(99)), (Some(2), None, None));
        assert!(!index.damaged && index.names == 0);
        // The older record naming has the bundle ahead and no `src/main`.
        assert_eq!(module("com.example.app/entry/ets/pages/Index").unwrap().unwrap(), index);

        let lib = module("&@scope/lib/src/main/js/lib&2.0.0").unwrap().unwrap();
        assert_eq!((lib.source_line(0), lib.names), (Some(3), 1));
        assert_eq!(module("&@scope/lib/src/main/js/lib&3.1.0").unwrap().unwrap().source(), None);
        assert!(module("&@scope/lib/src/main/js/lib&9.9.9").is_none());

        // The older key is the path alone.
        let old = module("&other/src/main/ets/Old&").unwrap().unwrap();
        assert_eq!((old.source_lines(), old.damaged), (&[Some(1)][..], true));

        assert!(matches!(module("&entry/src/main/ets/broken&"), Some(Err(SourceMapError::Module { .. }))));
        assert!(module("&entry/src/main/ets/pages/Missing&").is_none() && module("&nonsense").is_none() && module("").is_none());
    }

    #[test]
    fn malformed_tables_are_errors_not_panics() {
        assert_eq!(SourceMaps::index(b"{}").unwrap().len(), 0);
        assert_eq!(SourceMaps::index(b" { \"a\" : [1, {\"b\": \"]\"}] , \"c\":null } ").unwrap().len(), 2);
        for text in ["", "[]", "{", "{\"a\"", "{\"a\":", "{\"a\":{", "{\"a\":\"x", "{\"a\":1,", "{\"a\":1 \"b\":2}", "{\"a\\", "{,}"] {
            assert!(matches!(SourceMaps::index(text.as_bytes()), Err(SourceMapError::Malformed { .. })), "{text}");
        }
        // Every prefix of a real table is either read or refused.
        for end in 0..TABLE.len() {
            let _ = SourceMaps::index(&TABLE.as_bytes()[..end]);
        }
        // A table indexed from other bytes does not read past the ones it is given.
        let maps = SourceMaps::index(TABLE.as_bytes()).unwrap();
        assert!(matches!(maps.module(b"{}", "&entry/src/main/ets/pages/Index&"), Some(Err(_))));
    }

    #[test]
    fn segments_decode_or_stop() {
        assert_eq!(segment(b"AAgBC"), Some(([0, 0, 16, 1, 0], 4)));
        assert_eq!(segment(b"D"), Some(([-1, 0, 0, 0, 0], 1)));
        assert_eq!(segment(b"A*"), None);
        // A continuation that never ends, and more fields than a segment has.
        assert_eq!(segment(b"gggggggggggggggg"), None);
        assert_eq!(segment(b"AAAAAA"), None);
        assert_eq!(segment(b"g"), None);
        // A source line that runs below zero maps nowhere.
        assert_eq!(decode_lines("AADA;AACA"), (vec![None, Some(1)], false));
    }
}
