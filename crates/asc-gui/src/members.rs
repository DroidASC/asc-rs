//! Method / field spans in disassembly lines, behind "find references to the
//! member under the caret" and Ctrl+click navigation. Pure logic, no egui.
//!
//! The smali writer is regular enough to parse back: references are
//! `Lcls;->name(params)ret` / `Lcls;->name:type`, declarations are
//! `.method <flags> name(params)ret` / `.field <flags> name:type [= value]`.
//! Member names cannot contain `(` or `:`, so a name runs up to the first of
//! them and may hold any other character, including Unicode or (DEX 040+)
//! ASCII spaces. The writer only separates tokens with ASCII spaces.

/// Method or field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Method,
    Field,
}

/// One member mentioned on a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSpan {
    /// Byte range in the line: the whole `Lcls;->name...` reference, or
    /// `name(params)ret` / `name:type` of a declaration.
    pub start: usize,
    pub end: usize,
    pub kind: MemberKind,
    /// Declaring class descriptor (the tab's class for a declaration).
    pub class: String,
    pub name: String,
    /// `(params)ret` for a method, the field type for a field.
    pub descriptor: String,
    /// A `.method` / `.field` line of the class itself.
    pub declaration: bool,
}

impl MemberSpan {
    /// Whether byte column `col` touches the span (its end included, so a
    /// caret placed right after the last character still counts).
    pub fn contains(&self, col: usize) -> bool {
        self.start <= col && col <= self.end
    }
}

/// Length of the type descriptor at the start of `s` (`I`, `[[J`, `Lcls;`).
fn type_descriptor_len(s: &str) -> Option<usize> {
    let dims = s.bytes().take_while(|&b| b == b'[').count();
    let rest = &s[dims..];
    match rest.as_bytes().first()? {
        b'L' => rest.find(';').map(|i| dims + i + 1),
        b'V' | b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' => Some(dims + 1),
        _ => None,
    }
}

/// Length of `(params)ret` at the start of `s`.
fn proto_len(s: &str) -> Option<usize> {
    if !s.starts_with('(') {
        return None;
    }
    let mut i = 1;
    while !s[i..].starts_with(')') {
        i += type_descriptor_len(&s[i..])?;
    }
    i += 1;
    Some(i + type_descriptor_len(&s[i..])?)
}

/// `name` + descriptor starting at `s`: the member kind, name length and the
/// total length.
fn member_tail(s: &str) -> Option<(MemberKind, usize, usize)> {
    let name_len = s.find(['(', ':'])?;
    let name = &s[..name_len];
    // No whitespace check: U+3000 and friends are valid in every DEX version,
    // ASCII spaces from 040 on. These characters never are.
    if name.is_empty() || name.contains(['\n', ',', '{', '}', ';', '"', ')']) {
        return None;
    }
    let rest = &s[name_len..];
    if rest.starts_with('(') {
        Some((MemberKind::Method, name_len, name_len + proto_len(rest)?))
    } else {
        Some((MemberKind::Field, name_len, name_len + 1 + type_descriptor_len(&rest[1..])?))
    }
}

/// Byte ranges of the double-quoted string literals on a line (smali escapes
/// a quote inside a literal as `\"`).
fn string_literals(line: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut open: Option<usize> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (c, open) {
            ('\\', Some(_)) => escaped = true,
            ('"', None) => open = Some(i),
            ('"', Some(s)) => {
                out.push((s, i + 1));
                open = None;
            }
            _ => {}
        }
    }
    if let Some(s) = open {
        out.push((s, line.len()));
    }
    out
}

/// Characters that end a class descriptor when walking back from its end.
/// Only ASCII whitespace separates tokens: a class name may hold U+3000 etc.
fn ends_descriptor(c: char) -> bool {
    c.is_ascii_whitespace() || matches!(c, ',' | '{' | '}' | '(' | ')' | '"' | '=' | ':' | ';')
}

/// Access-flag words `asc-smali` writes before a field / method name, in its
/// emission order (`FIELD_FLAGS` / `METHOD_FLAGS` there).
const FIELD_FLAG_WORDS: &[&str] = &["public", "private", "protected", "static", "final", "volatile", "transient", "synthetic", "enum"];
const METHOD_FLAG_WORDS: &[&str] = &[
    "public",
    "private",
    "protected",
    "static",
    "final",
    "synchronized",
    "bridge",
    "varargs",
    "native",
    "abstract",
    "strictfp",
    "synthetic",
    "constructor",
    "declared-synchronized",
];

/// Byte offset of the name in `rest` (the text after `.method ` / `.field `):
/// skips the flag words, each at most once and in emission order, so a name
/// holding spaces (`my test`) is kept whole.
fn skip_flags(rest: &str, words: &[&str]) -> usize {
    let mut at = 0;
    for w in words {
        if rest[at..].strip_prefix(w).is_some_and(|r| r.starts_with(' ')) {
            at += w.len() + 1;
        }
    }
    at
}

/// The declaration on a `.method` / `.field` line of `class`.
pub(crate) fn declaration(line: &str, class: &str) -> Option<MemberSpan> {
    let body = line.trim_start();
    let indent = line.len() - body.len();
    let (head, kind, words) = if body.starts_with(".method ") {
        (".method ", MemberKind::Method, METHOD_FLAG_WORDS)
    } else if body.starts_with(".field ") {
        (".field ", MemberKind::Field, FIELD_FLAG_WORDS)
    } else {
        return None;
    };
    let start = head.len() + skip_flags(&body[head.len()..], words);
    let (k, name_len, len) = member_tail(&body[start..])?;
    if k != kind {
        return None;
    }
    Some(MemberSpan {
        start: indent + start,
        end: indent + start + len,
        kind,
        class: class.to_string(),
        name: body[start..start + name_len].to_string(),
        descriptor: body[start + name_len..start + len].trim_start_matches(':').to_string(),
        declaration: true,
    })
}

/// Whether `class` is a whole member-receiver descriptor: `Lcls;` or an
/// array of any element type (`[I`, `[[Lcls;`).
fn is_receiver(class: &str) -> bool {
    let element = class.trim_start_matches('[');
    let object = element.starts_with('L') && element.len() >= 3;
    (object || class.starts_with('[')) && type_descriptor_len(class) == Some(class.len())
}

/// Every member reference and declaration on a line, in order. `class` is the
/// descriptor of the class the line belongs to (declarations name no class).
pub fn member_spans_in_line(line: &str, class: &str) -> Vec<MemberSpan> {
    let mut out: Vec<MemberSpan> = declaration(line, class).into_iter().collect();
    let literals = string_literals(line);
    let in_literal = |pos: usize| literals.iter().any(|&(s, e)| s <= pos && pos < e);
    let mut from = 0;
    while let Some(rel) = line[from..].find("->") {
        let arrow = from + rel;
        let arrow_end = arrow + 2;
        from = arrow_end;
        if in_literal(arrow) {
            continue;
        }
        // An object class ends in `;`; a primitive array (`[I`) does not.
        let scan_end = if line[..arrow].ends_with(';') { arrow - 1 } else { arrow };
        let start = line[..scan_end].char_indices().rev().find(|&(_, c)| ends_descriptor(c)).map_or(0, |(i, c)| i + c.len_utf8());
        let class = &line[start..arrow];
        if !is_receiver(class) {
            continue;
        }
        let Some((kind, name_len, len)) = member_tail(&line[arrow_end..]) else { continue };
        let tail = &line[arrow_end..arrow_end + len];
        out.push(MemberSpan {
            start,
            end: arrow_end + len,
            kind,
            class: class.to_string(),
            name: tail[..name_len].to_string(),
            descriptor: tail[name_len..].trim_start_matches(':').to_string(),
            declaration: false,
        });
        from = arrow_end + len;
    }
    out
}

/// The member touching byte column `col` of `line`.
pub fn member_at(line: &str, class: &str, col: usize) -> Option<MemberSpan> {
    member_spans_in_line(line, class).into_iter().find(|s| s.contains(col))
}

/// Index of the line declaring member `name` of `kind`; with a `descriptor`
/// only the declaration with that prototype / type matches (overloads).
pub fn declaration_line(lines: &[String], class: &str, kind: MemberKind, name: &str, descriptor: Option<&str>) -> Option<usize> {
    lines.iter().position(|l| {
        declaration(l, class).is_some_and(|d| d.kind == kind && d.name == name && descriptor.is_none_or(|want| d.descriptor == want))
    })
}

/// Byte offset of character `char_idx` in `s` (clamped to its length).
pub fn char_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map_or(s.len(), |(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLS: &str = "Lcom/x/Foo;";

    fn lines(s: &str) -> Vec<String> {
        s.lines().map(str::to_string).collect()
    }

    fn one(line: &str) -> MemberSpan {
        let mut v = member_spans_in_line(line, CLS);
        assert_eq!(v.len(), 1, "{line}: {v:?}");
        v.remove(0)
    }

    #[test]
    fn method_and_field_references() {
        let line = "    invoke-virtual {p0, v1}, Lcom/x/Bar;->run(I[Ljava/lang/String;)Ljava/lang/Long;";
        let s = one(line);
        assert_eq!((s.kind, s.class.as_str(), s.name.as_str()), (MemberKind::Method, "Lcom/x/Bar;", "run"));
        assert_eq!(s.descriptor, "(I[Ljava/lang/String;)Ljava/lang/Long;");
        assert_eq!(&line[s.start..s.end], "Lcom/x/Bar;->run(I[Ljava/lang/String;)Ljava/lang/Long;");
        assert!(!s.declaration);

        let line = "    sget-object v0, Lcom/x/Bar;->INSTANCE:Lcom/x/Bar;";
        let s = one(line);
        assert_eq!((s.kind, s.name.as_str(), s.descriptor.as_str()), (MemberKind::Field, "INSTANCE", "Lcom/x/Bar;"));
        assert_eq!(&line[s.start..s.end], "Lcom/x/Bar;->INSTANCE:Lcom/x/Bar;");

        let s = one("    invoke-direct {p0}, Ljava/lang/Object;-><init>()V");
        assert_eq!((s.name.as_str(), s.descriptor.as_str()), ("<init>", "()V"));
        let s = one("    iget-wide v0, p0, Lcom/x/Bar;->count:J");
        assert_eq!(s.descriptor, "J");
    }

    #[test]
    fn array_classes_inner_classes_and_unicode_names() {
        let s = one("    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;");
        assert_eq!(s.class, "[Ljava/lang/Object;");
        let s = one("    invoke-static {}, Lcom/x/Y$Z;->get$default()V");
        assert_eq!((s.class.as_str(), s.name.as_str()), ("Lcom/x/Y$Z;", "get$default"));
        let line = "    sput v0, Ll/\u{06e1};->\u{1a7b}\u{1F600}:I";
        let s = one(line);
        assert_eq!((s.class.as_str(), s.name.as_str()), ("Ll/\u{06e1};", "\u{1a7b}\u{1F600}"));
        assert_eq!(s.end, line.len());
    }

    #[test]
    fn several_references_on_one_line() {
        let line = "    .enum Lcom/x/E;->A:Lcom/x/E; # see Lcom/x/F;->b()V";
        let v = member_spans_in_line(line, CLS);
        assert_eq!(v.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec!["A", "b"]);
        assert!(v[0].end < v[1].start);
    }

    #[test]
    fn string_literals_are_not_references() {
        assert!(member_spans_in_line("    const-string v0, \"Lcom/x/Bar;->run()V\"", CLS).is_empty());
        assert!(member_spans_in_line("    const-string v0, \"a\\\" Lcom/x/Bar;->run()V\"", CLS).is_empty());
        // A reference after a closed literal still counts.
        let v = member_spans_in_line("    .annotation x = \"q\" Lcom/x/Bar;->f:I", CLS);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn malformed_references_are_skipped() {
        assert!(member_spans_in_line("    # foo;->bar", CLS).is_empty());
        assert!(member_spans_in_line("    Lcom/x/Bar;->run(Q)V", CLS).is_empty());
        assert!(member_spans_in_line("    Lcom/x/Bar;->f:", CLS).is_empty());
        assert!(member_spans_in_line("    Lcom/x/Bar;->(I)V", CLS).is_empty());
        assert!(member_spans_in_line("    L;->run()V", CLS).is_empty());
        // Switch payload targets and arrows without a receiver.
        assert!(member_spans_in_line("        0x1 -> :sswitch_0", CLS).is_empty());
        assert!(member_spans_in_line("    a->b()V", CLS).is_empty());
        assert!(member_spans_in_line("    [Q->clone()V", CLS).is_empty());
        assert!(member_spans_in_line("    [->clone()V", CLS).is_empty());
    }

    #[test]
    fn primitive_array_receivers() {
        let line = "    invoke-virtual {v0}, [I->clone()Ljava/lang/Object;";
        let s = one(line);
        assert_eq!(
            (s.kind, s.class.as_str(), s.name.as_str(), s.descriptor.as_str()),
            (MemberKind::Method, "[I", "clone", "()Ljava/lang/Object;")
        );
        assert_eq!(&line[s.start..s.end], "[I->clone()Ljava/lang/Object;");
        assert_eq!(one("    invoke-virtual {v1}, [[J->clone()Ljava/lang/Object;").class, "[[J");
        assert_eq!(one("    invoke-virtual {v1}, [[Ljava/lang/String;->clone()Ljava/lang/Object;").class, "[[Ljava/lang/String;");
        assert_eq!(one("    iget v0, v1, [F->length:I").name, "length");
    }

    #[test]
    fn names_with_spaces_and_unicode_whitespace() {
        // U+3000 / U+1680 are valid SimpleName characters in every DEX version.
        let s = one("    sget v0, Lcom/x/a\u{3000}b;->f:I");
        assert_eq!((s.class.as_str(), s.name.as_str()), ("Lcom/x/a\u{3000}b;", "f"));
        let s = one("    sget v0, Lcom/x/Bar;->\u{3000}:I");
        assert_eq!(s.name, "\u{3000}");
        assert_eq!(one("    sget v0, Lcom/x/Bar;->a\u{1680}b:I").name, "a\u{1680}b");
        // ASCII spaces (DEX 040+, Kotlin backtick names).
        let line = "    invoke-static {}, Lcom/x/Bar;->my test()V";
        let s = one(line);
        assert_eq!((s.name.as_str(), &line[s.start..s.end]), ("my test", "Lcom/x/Bar;->my test()V"));
        assert_eq!(one("    invoke-static {}, Lcom/x/Bar;-> run()V").name, " run");

        let s = one(".field public a b:I");
        assert_eq!((s.name.as_str(), s.descriptor.as_str(), s.declaration), ("a b", "I", true));
        let line = ".method public final my test()V";
        let s = one(line);
        assert_eq!((s.name.as_str(), &line[s.start..s.end]), ("my test", "my test()V"));
        assert_eq!(one(".method \u{3000}()V").name, "\u{3000}");
        assert_eq!(one(".field private static a\u{00a0}b:I = 0x1").name, "a\u{00a0}b");
        // A name equal to a flag word is not a flag when no space follows it.
        assert_eq!(one(".method public final()V").name, "final");
        assert_eq!(one(".method public declared-synchronized go()V").name, "go");
        let l = lines(".class Lcom/x/Foo;\n.method public final my test()V\n.end method\n.method public test()V");
        assert_eq!(declaration_line(&l, CLS, MemberKind::Method, "test", None), Some(3));
        assert_eq!(declaration_line(&l, CLS, MemberKind::Method, "my test", Some("()V")), Some(1));
    }

    #[test]
    fn declarations() {
        let line = ".method public static final synthetic run(ILjava/lang/String;)V";
        let s = one(line);
        assert!(s.declaration);
        assert_eq!((s.kind, s.class.as_str(), s.name.as_str()), (MemberKind::Method, CLS, "run"));
        assert_eq!(s.descriptor, "(ILjava/lang/String;)V");
        assert_eq!(&line[s.start..s.end], "run(ILjava/lang/String;)V");

        let s = one(".method public constructor <init>()V");
        assert_eq!(s.name, "<init>");

        let line = ".field private static final TAG:Ljava/lang/String; = \"a:b\"";
        let s = one(line);
        assert_eq!((s.kind, s.name.as_str(), s.descriptor.as_str()), (MemberKind::Field, "TAG", "Ljava/lang/String;"));
        assert_eq!(&line[s.start..s.end], "TAG:Ljava/lang/String;");

        // A field initialised with a member constant: declaration first.
        let v = member_spans_in_line(".field static final M:Ljava/lang/reflect/Method; = Lcom/x/Bar;->m()V", CLS);
        assert_eq!(v.len(), 2);
        assert!(v[0].declaration && !v[1].declaration);
        assert_eq!(v[1].name, "m");

        assert!(member_spans_in_line(".end method", CLS).is_empty());
        assert!(member_spans_in_line(".class public Lcom/x/Foo;", CLS).is_empty());
    }

    #[test]
    fn caret_hit_testing() {
        let line = "    invoke-static {}, Lcom/x/Bar;->run()V";
        let start = line.find('L').unwrap();
        assert!(member_at(line, CLS, start - 1).is_none());
        assert_eq!(member_at(line, CLS, start).unwrap().name, "run");
        assert_eq!(member_at(line, CLS, line.len()).unwrap().name, "run");
        assert!(member_at("    return-void", CLS, 6).is_none());
    }

    #[test]
    fn declaration_lines_respect_overloads() {
        let l = lines(
            ".class public Lcom/x/Foo;\n.field public run:I\n.method public run()V\n.end method\n.method public run(I)V\n.end method",
        );
        assert_eq!(declaration_line(&l, CLS, MemberKind::Method, "run", None), Some(2));
        assert_eq!(declaration_line(&l, CLS, MemberKind::Method, "run", Some("(I)V")), Some(4));
        assert_eq!(declaration_line(&l, CLS, MemberKind::Method, "run", Some("(J)V")), None);
        assert_eq!(declaration_line(&l, CLS, MemberKind::Field, "run", Some("I")), Some(1));
        assert_eq!(declaration_line(&l, CLS, MemberKind::Field, "ru", None), None);
    }

    #[test]
    fn char_offsets() {
        assert_eq!(char_to_byte("a\u{06e1}b", 0), 0);
        assert_eq!(char_to_byte("a\u{06e1}b", 2), 3);
        assert_eq!(char_to_byte("a\u{06e1}b", 9), 4);
    }
}
