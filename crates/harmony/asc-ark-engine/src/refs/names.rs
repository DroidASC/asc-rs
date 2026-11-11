//! Searches by the text of a string: `string:`, `prop:` and `global:`.
//!
//! All three locate first: the ids of the matching strings are found once
//! per region, and the code scan compares ids. They differ in which
//! instructions count: every string operand and the strings of literal
//! arrays for `string:`, the by-name property instructions for `prop:`, the
//! by-name global instructions for `global:`.
//!
//! `string:` also reads what is no instruction: the record fields that hold
//! strings, and the annotations of the program (`@interface`), whose values
//! are named by file offset from the function that carries them and, for
//! the defaults, from the fields of the annotation interface:
//!
//! ```text
//! a.abc | &entry/src/main/ets/Net&->#~@0>#load | Net.load | annotation @&entry/src/main/ets/Marks&.Route path="/pay", tags[1]="pay"
//! a.abc | &entry/src/main/ets/Marks&.Route field path | - | annotation default "/"
//! ```

use std::collections::HashMap;

use asc_abc::{Abc, ClassEntry, ElementValue, FieldType, Literal, MethodTag, RecordKind, RecordName, StringData, record_field};
use asc_arkisa::{DecodeError, OperandKind};
use memchr::memmem;
use regex::Regex;

use super::{
    AnnotationHit, Condition, Env, Function, Hit, IdSet, MAX_LITERAL_DEPTH, Pattern, Record, RecordHit, Worker, chunks, pc_of, run_units,
};
use crate::ops::{Access, NameUse, OpTable};
use crate::track::{Effects, Source, Tracker};
use crate::{Result, text};

/// A pattern ready to test the strings of a file.
pub(crate) enum Matcher<'q> {
    Regex(&'q Regex),
    /// The needle is also valid MUTF-8, so raw string bytes can be searched.
    Bytes(Box<memmem::Finder<'q>>),
    /// The needle holds NUL or a supplementary character, which MUTF-8
    /// encodes differently: compare decoded text.
    Decoded(&'q str),
    /// The whole string is this.
    Exact(&'q str),
}

/// Whether MUTF-8 encodes `text` as UTF-8 does.
fn is_plain(text: &str) -> bool {
    text.chars().all(|c| c != '\0' && u32::from(c) < 0x1_0000)
}

impl<'q> Matcher<'q> {
    pub(crate) fn contains(needle: &'q str) -> Matcher<'q> {
        if is_plain(needle) { Matcher::Bytes(Box::new(memmem::Finder::new(needle.as_bytes()))) } else { Matcher::Decoded(needle) }
    }

    pub(crate) fn of(pattern: &'q Pattern) -> Matcher<'q> {
        match pattern {
            Pattern::Regex(regex) => Matcher::Regex(regex),
            Pattern::Contains(needle) => Matcher::contains(needle),
            Pattern::Exact(name) => Matcher::Exact(name),
        }
    }

    pub(crate) fn matches(&self, string: &StringData<'_>) -> bool {
        match self {
            Matcher::Regex(regex) => regex.is_match(&string.to_str()),
            Matcher::Bytes(finder) => finder.find(string.bytes).is_some(),
            Matcher::Decoded(needle) => string.to_str().contains(needle),
            Matcher::Exact(name) => string.bytes == name.as_bytes() || (!is_plain(name) && string.to_str() == *name),
        }
    }

    /// Where `text`, a decoded string that [`Matcher::matches`], matches
    /// first: a byte range of it.
    pub(crate) fn find(&self, text: &str) -> Option<std::ops::Range<usize>> {
        match self {
            Matcher::Regex(regex) => regex.find(text).map(|found| found.range()),
            Matcher::Bytes(finder) => finder.find(text.as_bytes()).map(|at| at..at + finder.needle().len()),
            Matcher::Decoded(needle) => text.find(needle).map(|at| at..at + needle.len()),
            Matcher::Exact(_) => Some(0..text.len()),
        }
    }

    /// Whether no string of `file` can match: the needle's bytes are nowhere
    /// in it.
    pub(crate) fn rules_out(&self, file: &[u8]) -> bool {
        match self {
            Matcher::Bytes(finder) => finder.find(file).is_none(),
            Matcher::Exact(name) if is_plain(name) => memmem::find(file, name.as_bytes()).is_none(),
            Matcher::Regex(_) | Matcher::Decoded(_) | Matcher::Exact(_) => false,
        }
    }
}

/// Which instructions a name search looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Every string operand, the strings of literal arrays and of record fields.
    Text,
    Property(Option<Access>),
    Global(Option<Access>),
}

/// The string operand is a 16-bit id of the region.
const STRING_ID: u8 = 1;
/// A 32-bit string operand of a `deprecated.*` opcode: a file offset.
const STRING_OFFSET: u8 = 2;
const LITERAL_ID: u8 = 4;
/// A 32-bit literal array operand of a `deprecated.*` opcode: a file offset.
const LITERAL_OFFSET: u8 = 8;
/// The [`Access`] of a property or global instruction, as its position in
/// [`Access::ALL`], above the flags.
const ACCESS_SHIFT: u8 = 4;

impl Scope {
    /// The flags of `opcode`: 0 when the search does not look at it.
    fn flags(self, opcode: &asc_arkisa::Opcode) -> u8 {
        let bit = |kind, narrow, wide| match opcode.operand_of(kind) {
            Some(operand) if operand.width > 16 => wide,
            Some(_) => narrow,
            None => 0,
        };
        let string = bit(OperandKind::StringId, STRING_ID, STRING_OFFSET);
        let wanted = |access: Access, filter: Option<Access>| {
            // A read may turn out to be the callee of a call: see `Names::classify`.
            let kept = filter.is_none_or(|filter| filter == access || (filter == Access::Call && access == Access::Read));
            let position: u8 = match access {
                Access::Read => 0,
                Access::Write => 1,
                Access::Define => 2,
                Access::Call => 3,
            };
            if kept { string | position << ACCESS_SHIFT } else { 0 }
        };
        match (self, NameUse::of(opcode)) {
            (Scope::Text, _) => string | bit(OperandKind::LiteralArrayId, LITERAL_ID, LITERAL_OFFSET),
            (Scope::Property(filter), Some(NameUse::Property(access))) => wanted(access, filter),
            (Scope::Global(filter), Some(NameUse::Global(access))) => wanted(access, filter),
            (Scope::Property(_) | Scope::Global(_), _) => 0,
        }
    }

    fn filter(self) -> Option<Access> {
        match self {
            Scope::Text => None,
            Scope::Property(filter) | Scope::Global(filter) => filter,
        }
    }
}

/// The access [`Scope::flags`] stored: its position in [`Access::ALL`].
fn access_of(flags: u8) -> Access {
    Access::ALL[usize::from(flags >> ACCESS_SHIFT) % Access::ALL.len()]
}

/// A prepared `string:` / `prop:` / `global:` search of one ABC entry.
pub(crate) struct Names<'q, 'a> {
    abc: Abc<'a>,
    matcher: Matcher<'q>,
    scope: Scope,
    /// The matching string ids of every region; `None` when the file cannot
    /// hold a match at all.
    ids: Option<IdSet>,
    operands: OpTable<u8>,
    /// For telling a property read that is called from one that is not.
    effects: Effects,
    /// File offsets of the annotation interfaces of the program that
    /// annotations of the file can name, in ascending order. Empty for a
    /// search that does not read annotations, and for a file without any:
    /// no function is asked for its annotations then.
    interfaces: Vec<u32>,
}

/// Classes tested per unit of work when the annotation interfaces are looked for.
const CLASS_CHUNK: usize = 1024;
/// The type of a string field.
const STRING_DESCRIPTOR: &[u8] = b"Lpanda.String;";

/// The annotation interfaces of the program in the class tables of the
/// file, which is where an annotation names its interface: every class
/// there but the compiler's own (`_ES…`), the types of fields and, of the
/// records of the file, those that are no annotation interface. One the
/// file only declares counts: nothing but its name is known.
fn program_interfaces(env: &Env<'_, '_>) -> Result<Vec<u32>> {
    let abc = env.abc;
    // A region whose header or table does not read names no interface.
    let tables = abc.regions().into_iter().flat_map(|regions| regions.iter()).filter_map(|region| region.class_table().ok());
    let mut classes: Vec<u32> = tables
        .flat_map(|table| (0..table.len()).filter_map(move |index| table.get(index)))
        // The other entries are the codes of primitive types.
        .filter_map(|entry| if let FieldType::Class(off) = FieldType::from_entry(entry) { Some(off) } else { None })
        .collect();
    classes.sort_unstable();
    classes.dedup();
    let is_interface = |off: u32| match abc.class_entry(off) {
        // The flag first: nearly every record is a module, whose name need not be read.
        Ok(ClassEntry::Local(class)) => class.is_annotation() && class.kind() == RecordKind::Annotation,
        Ok(foreign @ ClassEntry::Foreign(_)) => {
            let descriptor = foreign.descriptor().bytes;
            descriptor.starts_with(b"L")
                && descriptor != STRING_DESCRIPTOR
                && !RecordName::parse(&String::from_utf8_lossy(foreign.name())).is_pseudo()
        }
        Err(_) => false,
    };
    // Every record of the file is looked at: on the threads of the search, like its strings.
    let units: Vec<std::ops::Range<usize>> = chunks(classes.len(), CLASS_CHUNK).collect();
    let found = run_units(units.len(), env.workers, env.cancel, |unit| {
        classes[units[unit].clone()].iter().copied().filter(|&off| is_interface(off)).collect::<Vec<u32>>()
    })?;
    Ok(found.into_iter().flatten().collect())
}

impl<'q, 'a> Names<'q, 'a> {
    pub(crate) fn prepare(env: &Env<'q, 'a>, matcher: Matcher<'q>, scope: Scope) -> Result<Names<'q, 'a>> {
        let abc = env.abc;
        let ids = if matcher.rules_out(abc.bytes()) {
            None
        } else {
            Some(IdSet::locate(env, |off| abc.string(off).is_ok_and(|string| matcher.matches(&string)))?)
        };
        // Asked for by a lone query only (`Worker::annotations`).
        let reads_annotations = scope == Scope::Text && env.is_lone && ids.is_some();
        let interfaces = if reads_annotations { program_interfaces(env)? } else { Vec::new() };
        Ok(Names { abc, matcher, scope, ids, operands: OpTable::build(|opcode| scope.flags(opcode)), effects: Effects::new(), interfaces })
    }
}

impl<'a> Condition<'a> for Names<'_, 'a> {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's> {
        Box::new(NamesWorker { names: self, by_offset: HashMap::new(), tracker: Tracker::default(), reads: Vec::new() })
    }

    fn is_impossible(&self) -> bool {
        self.ids.is_none()
    }
}

struct NamesWorker<'s, 'q, 'a> {
    names: &'s Names<'q, 'a>,
    /// Whether the string at a file offset matches, for strings named by
    /// offset (literal array items, record fields).
    by_offset: HashMap<u32, bool>,
    tracker: Tracker,
    /// Offsets of the property reads of the function being scanned.
    reads: Vec<u32>,
}

/// A matched `STRING` item of a literal array: its position (`[2]`, or
/// `[2][0]` inside a nested array) and the text.
struct LiteralHit {
    position: String,
    value: String,
}

impl<'a> NamesWorker<'_, '_, 'a> {
    fn offset_matches(&mut self, off: u32) -> Option<StringData<'a>> {
        let string = self.names.abc.string(off).ok()?;
        let matcher = &self.names.matcher;
        self.by_offset.entry(off).or_insert_with(|| matcher.matches(&string)).then_some(string)
    }

    fn literal_hits(&mut self, off: u32, prefix: &str, depth: usize, hits: &mut Vec<LiteralHit>) {
        let Ok(array) = self.names.abc.literal_array(off) else { return };
        // Items past a malformed one are unreachable; the ones before it still count.
        for (index, literal) in array.iter().map_while(|literal| literal.ok()).enumerate() {
            match literal {
                Literal::String(string_off) => {
                    if let Some(string) = self.offset_matches(string_off) {
                        hits.push(LiteralHit { position: format!("{prefix}[{index}]"), value: string.to_str().into_owned() });
                    }
                }
                Literal::LiteralArray(nested) if depth < MAX_LITERAL_DEPTH => {
                    self.literal_hits(nested, &format!("{prefix}[{index}]"), depth + 1, hits);
                }
                _ => {}
            }
        }
    }

    /// `literal@0x1a2b [0]="a", [3]="b"`; a string longer than a row shows
    /// is cut, and says where it matches.
    fn literal_text(&self, off: u32, hits: &[LiteralHit]) -> String {
        let mut out = format!("literal@{off:#x} ");
        for (i, hit) in hits.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&hit.position);
            out.push('=');
            out.push_str(&text::quoted_match(&hit.value, self.names.matcher.find(&hit.value)));
        }
        out
    }

    /// `"plain"`, or `[0]="a", [2]="b"`: the matched strings of the value
    /// at `off` of an annotation element or of a field of an annotation
    /// interface, which is a string or an array as `is_array` says. Each
    /// is added to `matched`; `None` when none matches.
    fn annotation_value(&mut self, off: u32, is_array: bool, prefix: &str, matched: &mut Vec<String>) -> Option<String> {
        if !is_array {
            let value = self.offset_matches(off)?.to_str().into_owned();
            let text = format!("{prefix}={}", text::quoted_match(&value, self.names.matcher.find(&value)));
            matched.push(value);
            return Some(text);
        }
        let mut found = Vec::new();
        self.literal_hits(off, prefix, 0, &mut found);
        if found.is_empty() {
            return None;
        }
        let matcher = &self.names.matcher;
        let items: Vec<String> =
            found.iter().map(|hit| format!("{}={}", hit.position, text::quoted_match(&hit.value, matcher.find(&hit.value)))).collect();
        matched.extend(found.into_iter().map(|hit| hit.value));
        Some(items.join(", "))
    }

    /// The default values of the elements of annotation interface `record`
    /// that match: one hit per field.
    fn interface_defaults(&mut self, record: &Record<'_, 'a>, hits: &mut Vec<RecordHit>) {
        let abc = self.names.abc;
        for field in record.fields.clone().map_while(|field| field.ok()) {
            let (Ok(name), Some(value), Ok(FieldType::Class(class))) = (field.name(), field.raw_value(), field.field_type()) else {
                continue;
            };
            let Ok(descriptor) = abc.string(class) else { continue };
            let is_array = descriptor.bytes.starts_with(b"[");
            if !is_array && descriptor.bytes != STRING_DESCRIPTOR {
                continue;
            }
            let mut matched = Vec::new();
            let Some(found) = self.annotation_value(value, is_array, "", &mut matched) else { continue };
            // A lone string has no position to follow.
            let found = found.strip_prefix('=').unwrap_or(&found);
            hits.push(RecordHit { field: name.to_str().into_owned(), matched, text: format!("annotation default {found}") });
        }
    }

    /// Label the property hits `hits[from..]` of `function` with their
    /// access and drop the ones the query does not ask for. A read whose
    /// value is the callee of a call in the same block is a `call`.
    ///
    /// A call that names its property itself (`callthisNwithname`, what
    /// `--enable-callable-name` compiles a method call to) still has the
    /// load in front of it, `ldobjbyname "cut"` … `callthis2withname "cut"`.
    /// The two are one call: the row is the call instruction, where
    /// `findrefs call` and the call graph put the call site, and the load
    /// is no row, of any access.
    fn classify(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>, from: usize, accesses: &[Access]) {
        let mut called = Vec::new();
        let mut absorbed = Vec::new();
        if !self.reads.is_empty() {
            let reads = &self.reads;
            // Code that does not decode was reported by the scan; its reads stay reads.
            let _ = self.tracker.run(&self.names.effects, &function.code, |frame, insn, call| {
                let callee = frame.value(call.callee);
                let Source::Property { name, .. } = callee.source else { return };
                if callee.pc != pc_of(insn) {
                    if reads.binary_search(&callee.pc).is_ok() {
                        called.push(callee.pc);
                    }
                    return;
                }
                // The callee was made by the call itself: it names the property. What the
                // accumulator holds is the load of that property the compiler put before it.
                let loaded = frame.value(frame.acc());
                if matches!(loaded.source, Source::Property { name: loaded, .. } if loaded == name)
                    && reads.binary_search(&loaded.pc).is_ok()
                {
                    absorbed.push(loaded.pc);
                }
            });
        }
        let filter = self.names.scope.filter();
        let found = hits.split_off(from);
        hits.extend(found.into_iter().zip(accesses).filter_map(|(mut hit, &access)| {
            let is_read = access == Access::Read;
            if is_read && absorbed.contains(&hit.pc) {
                return None;
            }
            let access = if is_read && called.contains(&hit.pc) { Access::Call } else { access };
            hit.text.push_str(" [");
            hit.text.push_str(access.label());
            hit.text.push(']');
            filter.is_none_or(|filter| filter == access).then_some(hit)
        }));
    }
}

impl<'a> Worker<'a> for NamesWorker<'_, '_, 'a> {
    fn record(&mut self, record: &Record<'_, 'a>, hits: &mut Vec<RecordHit>) -> bool {
        if self.names.scope != Scope::Text {
            return true;
        }
        // The flag first: the name of a module need not be read.
        if record.class.is_annotation() && record.class.kind() == RecordKind::Annotation {
            self.interface_defaults(record, hits);
            return true;
        }
        // A malformed field is reported by the scan, when the methods are reached through it.
        for field in record.fields.clone().map_while(|field| field.ok()) {
            let (Ok(name), Some(value)) = (field.name(), field.raw_value()) else { continue };
            let (matched, text) = match name.bytes {
                record_field::SCOPE_NAMES => {
                    let mut found = Vec::new();
                    self.literal_hits(value, "", 0, &mut found);
                    if found.is_empty() {
                        continue;
                    }
                    let text = self.literal_text(value, &found);
                    (found.into_iter().map(|hit| hit.value).collect(), text)
                }
                record_field::JSON_FILE_CONTENT => {
                    let Some(string) = self.offset_matches(value) else { continue };
                    let value = string.to_str().into_owned();
                    let text = text::quoted_match(&value, self.names.matcher.find(&value));
                    (vec![value], text)
                }
                _ => continue,
            };
            hits.push(RecordHit { field: name.to_str().into_owned(), matched, text });
        }
        true
    }

    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError> {
        let names = self.names;
        let Some(ids) = &names.ids else { return Ok(()) };
        let from = hits.len();
        let mut accesses = Vec::new();
        self.reads.clear();
        let mut walked = Ok(());
        for insn in asc_arkisa::walk(function.code.instructions()) {
            let insn = match insn {
                Ok(insn) => insn,
                // The walk ends here; the hits found before it stay.
                Err(err) => {
                    walked = Err(err);
                    break;
                }
            };
            let flags = names.operands.of(insn.opcode);
            if flags == 0 {
                continue;
            }
            let mut matched = Vec::new();
            let mut text = String::new();
            if flags & (STRING_ID | STRING_OFFSET) != 0 {
                let Some(id) = insn.string_id() else { continue };
                let string = if flags & STRING_ID != 0 {
                    ids.contains(function.region, id).then(|| function.table.get(id)).flatten().and_then(|off| names.abc.string(off).ok())
                } else {
                    self.offset_matches(id)
                };
                if let Some(string) = string {
                    let string = string.to_str().into_owned();
                    // The listing cuts a long operand; the match may lie beyond the cut.
                    text = function.text(&insn);
                    if let Some(excerpt) = text::excerpt_beyond(&string, names.matcher.find(&string)) {
                        text.push_str(" ; ");
                        text.push_str(&excerpt);
                    }
                    matched.push(string);
                }
            }
            if flags & (LITERAL_ID | LITERAL_OFFSET) != 0 {
                let Some(id) = insn.literal_array_id() else { continue };
                let off = if flags & LITERAL_ID != 0 { function.table.get(id) } else { Some(id) };
                let mut found = Vec::new();
                if let Some(off) = off {
                    self.literal_hits(off, "", 0, &mut found);
                }
                if let (Some(off), false) = (off, found.is_empty()) {
                    if !text.is_empty() {
                        text.push_str(" ; ");
                    } else {
                        text.push_str(insn.opcode.name);
                        text.push(' ');
                    }
                    text.push_str(&self.literal_text(off, &found));
                    matched.extend(found.into_iter().map(|hit| hit.value));
                }
            }
            if matched.is_empty() {
                continue;
            }
            if names.scope != Scope::Text {
                let access = access_of(flags);
                if access == Access::Read && matches!(names.scope, Scope::Property(_)) {
                    self.reads.push(pc_of(&insn));
                }
                accesses.push(access);
            }
            hits.push(Hit { pc: pc_of(&insn), matched, text });
        }
        if names.scope != Scope::Text {
            self.classify(function, hits, from, &accesses);
        }
        walked
    }

    fn annotations(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<AnnotationHit>) {
        if self.names.interfaces.is_empty() {
            return;
        }
        let abc = self.names.abc;
        // A tag list that does not read is reported when the function is listed.
        for tag in function.method.tags().map_while(|tag| tag.ok()) {
            let (MethodTag::Annotation(off) | MethodTag::RuntimeAnnotation(off)) = tag else { continue };
            let Ok(annotation) = abc.annotation(off) else { continue };
            let Ok(interface) = annotation.class_off(&abc) else { continue };
            if self.names.interfaces.binary_search(&interface).is_err() {
                continue;
            }
            let mut matched = Vec::new();
            let mut found = Vec::new();
            for element in annotation.elements() {
                let (off, is_array) = match element.typed(&abc) {
                    Ok(ElementValue::String(off)) => (off, false),
                    Ok(ElementValue::Array(off)) => (off, true),
                    Ok(ElementValue::Bool(_) | ElementValue::Int(_) | ElementValue::F64(_) | ElementValue::Other(_)) | Err(_) => continue,
                };
                let name = abc.string(element.name_off).map(|name| name.to_str().into_owned()).unwrap_or_default();
                found.extend(self.annotation_value(off, is_array, &name, &mut matched));
            }
            if found.is_empty() {
                continue;
            }
            let interface = abc.class_entry(interface).map(|class| String::from_utf8_lossy(class.name()).into_owned()).unwrap_or_default();
            hits.push(AnnotationHit { matched, text: format!("annotation @{interface} {}", found.join(", ")) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(scope: Scope, name: &str) -> Vec<u8> {
        asc_arkisa::opcodes().filter(|op| op.name == name).map(|op| scope.flags(op)).collect()
    }

    #[test]
    fn text_scope_covers_every_string_and_literal_operand() {
        assert_eq!(flags(Scope::Text, "lda.str"), [STRING_ID]);
        assert_eq!(flags(Scope::Text, "ldobjbyname"), [STRING_ID, STRING_ID]);
        assert_eq!(flags(Scope::Text, "createarraywithbuffer"), [LITERAL_ID, LITERAL_ID]);
        assert_eq!(flags(Scope::Text, "deprecated.ldobjbyname"), [STRING_OFFSET]);
        assert_eq!(flags(Scope::Text, "ldai"), [0]);
        let with_string = asc_arkisa::opcodes().filter(|op| Scope::Text.flags(op) & (STRING_ID | STRING_OFFSET) != 0).count();
        assert_eq!(with_string, asc_arkisa::opcodes().filter(|op| op.operand_of(OperandKind::StringId).is_some()).count());
    }

    #[test]
    fn property_and_global_scopes_follow_the_access() {
        let call = |position: u8| position << ACCESS_SHIFT;
        assert_eq!(flags(Scope::Property(None), "stobjbyname"), [STRING_ID | call(1), STRING_ID | call(1)]);
        assert_eq!(flags(Scope::Property(None), "definefieldbyname"), [STRING_ID | call(2)]);
        assert_eq!(flags(Scope::Property(None), "wide.callthisrangewithname"), [STRING_ID | call(3)]);
        assert_eq!(flags(Scope::Property(None), "deprecated.ldobjbyname"), [STRING_OFFSET]);
        assert_eq!(flags(Scope::Property(None), "lda.str"), [0]);
        assert_eq!(flags(Scope::Property(None), "tryldglobalbyname"), [0, 0]);
        // A filter keeps its own instructions; `call` also the reads, which may be callees.
        assert_eq!(flags(Scope::Property(Some(Access::Write)), "ldobjbyname"), [0, 0]);
        assert_eq!(flags(Scope::Property(Some(Access::Call)), "ldobjbyname"), [STRING_ID, STRING_ID]);
        assert_eq!(flags(Scope::Property(Some(Access::Call)), "stobjbyname"), [0, 0]);
        assert_eq!(flags(Scope::Global(None), "trystglobalbyname"), [STRING_ID | call(1), STRING_ID | call(1)]);
        assert_eq!(flags(Scope::Global(Some(Access::Read)), "stglobalvar"), [0]);
        assert_eq!(flags(Scope::Global(None), "ldobjbyname"), [0, 0]);
        assert_eq!(access_of(STRING_ID | call(3)), Access::Call);
    }

    #[test]
    fn needles_pick_the_cheapest_sound_matcher() {
        let plain = Matcher::contains("https://");
        assert!(matches!(plain, Matcher::Bytes(_)));
        assert!(plain.rules_out(b"no url here") && !plain.rules_out(b"x https://y"));
        assert!(matches!(Matcher::contains("\u{1f600}"), Matcher::Decoded(_)));
        let exact = Matcher::Exact("request");
        assert!(exact.rules_out(b"requires") && !exact.rules_out(b"a request b"));
        assert!(exact.matches(&StringData { utf16_len: 7, is_ascii: true, bytes: b"request" }));
        assert!(!exact.matches(&StringData { utf16_len: 8, is_ascii: true, bytes: b"requests" }));
    }
}
