//! A disassembled class as an agent reads it: its methods picked by name or
//! signature, or an outline when the whole class is too long to send.

/// One `.method` … `.end method` block of a class's smali.
pub struct MethodBlock<'a> {
    /// `name(params)ret`.
    pub signature: &'a str,
    /// The `.method` line (access flags and signature).
    pub declaration: &'a str,
    /// The block, from `.method` to `.end method` and its newline.
    pub text: &'a str,
}

impl MethodBlock<'_> {
    pub fn name(&self) -> &str {
        self.signature.split('(').next().unwrap_or(self.signature)
    }

    /// Instructions in the body (lines that are not directives, labels or comments).
    fn instructions(&self) -> usize {
        self.text.lines().skip(1).map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(['.', ':', '#'])).count()
    }
}

/// A class's smali split into its header and its methods.
pub struct ClassText<'a> {
    /// Up to the first field or method (`.class`, `.super`, `.source`, interfaces).
    pub header: &'a str,
    /// `.field` lines.
    pub fields: Vec<&'a str>,
    pub methods: Vec<MethodBlock<'a>>,
}

/// Section comments asc-smali writes before fields and methods.
const SECTIONS: &[&str] = &["# static fields", "# instance fields", "# direct methods", "# virtual methods"];

impl<'a> ClassText<'a> {
    pub fn parse(source: &'a str) -> ClassText<'a> {
        if source.starts_with(".class ") || source.contains("\n.method ") {
            Self::parse_smali(source)
        } else {
            Self::parse_source(source)
        }
    }

    fn parse_smali(smali: &'a str) -> ClassText<'a> {
        let mut header_end = None;
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        let mut open: Option<(usize, &str)> = None;
        let mut pos = 0;
        for line in smali.split_inclusive('\n') {
            let t = line.trim_end();
            let starts_body = t.starts_with(".field") || t.starts_with(".method ") || SECTIONS.contains(&t);
            if header_end.is_none() && starts_body {
                header_end = Some(pos);
            }
            if t.starts_with(".field") {
                fields.push(t);
            } else if t.starts_with(".method ") {
                open = Some((pos, t));
            } else if t == ".end method" {
                if let Some((start, declaration)) = open.take() {
                    let signature = declaration.split_whitespace().last().unwrap_or(declaration);
                    methods.push(MethodBlock { signature, declaration, text: &smali[start..pos + line.len()] });
                }
            }
            pos += line.len();
        }
        ClassText { header: &smali[..header_end.unwrap_or(smali.len())], fields, methods }
    }

    fn parse_source(src: &'a str) -> ClassText<'a> {
        let mut header_end = None;
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        // (start, declaration, signature, indent of the closing `}`)
        let mut open: Option<(usize, &'a str, &'a str, usize)> = None;
        let mut pos = 0;
        for line in src.split_inclusive('\n') {
            let raw = line.trim_end_matches('\n');
            let indent = raw.len() - raw.trim_start().len();
            let text = raw.trim_start();
            if let Some((start, decl, sig, member_indent)) = open {
                if text.trim_end() == "}" && indent == member_indent {
                    methods.push(MethodBlock { signature: sig, declaration: decl, text: &src[start..pos + line.len()] });
                    open = None;
                }
                pos += line.len();
                continue;
            }
            // Members sit at 4 spaces, or 8 inside a Kotlin `companion object`.
            if (indent == 4 || indent == 8) && !text.is_empty() {
                // `// @id/name` annotations appended to the line are not code.
                let code = strip_line_comment(text).trim_end();
                if !code.is_empty() && !code.starts_with(['/', '*', '@', '}', ')']) && !is_type_decl(code) {
                    let decl = code.strip_suffix(" {").unwrap_or(code.strip_suffix(';').unwrap_or(code));
                    let decl = &src[pos + (raw.len() - text.len())..pos + (raw.len() - text.len()) + decl.len()];
                    if let Some(sig) = source_method_sig(code) {
                        if header_end.is_none() {
                            header_end = Some(pos);
                        }
                        if code.ends_with('{') {
                            open = Some((pos, decl, sig, indent));
                        } else {
                            methods.push(MethodBlock { signature: sig, declaration: decl, text: &src[pos..pos + line.len()] });
                        }
                    } else if is_field_line(code) {
                        if header_end.is_none() {
                            header_end = Some(pos);
                        }
                        fields.push(&src[pos..pos + raw.len()]);
                    }
                }
            }
            pos += line.len();
        }
        ClassText { header: &src[..header_end.unwrap_or(src.len())], fields, methods }
    }

    /// The methods `query` names: an exact signature, a signature prefix
    /// (`onCreate(Landroid/os/Bundle;`), a Java-style signature
    /// (`onCreate(android.os.Bundle)`), or a bare name (every overload).
    /// `Lcls;->` in front is ignored, and so is whitespace.
    pub fn select(&self, query: &str) -> Vec<&MethodBlock<'a>> {
        let q: String = query.split_whitespace().collect();
        let q = q.rsplit_once("->").map_or(q.as_str(), |(_, m)| m);
        let exact: Vec<_> = self.methods.iter().filter(|m| m.signature == q).collect();
        if !exact.is_empty() {
            return exact;
        }
        if !q.contains('(') {
            return self.methods.iter().filter(|m| m.name() == q).collect();
        }
        let prefixed: Vec<_> = self.methods.iter().filter(|m| m.signature.starts_with(q)).collect();
        if !prefixed.is_empty() {
            return prefixed;
        }
        // `name(java.lang.String,int)`: compare its Dalvik form, return type optional.
        let member = query.rsplit_once("->").map_or(query, |(_, m)| m);
        let Some(dalvik) = asc_engine::names::java_signature_to_dalvik(member) else { return Vec::new() };
        self.methods.iter().filter(|m| m.signature == dalvik || m.signature.starts_with(&dalvik)).collect()
    }

    /// The header and `picked` methods, as smali.
    pub fn with_methods(&self, picked: &[&MethodBlock<'_>]) -> String {
        let mut out = self.header.trim_end().to_string();
        out.push('\n');
        for m in picked {
            out.push('\n');
            out.push_str(m.text);
        }
        out
    }

    /// Header, fields, and one line per method with its size, for a class
    /// of `bytes` over the `budget`.
    pub fn outline(&self, bytes: usize, budget: usize) -> String {
        let mut out = self.header.trim_end().to_string();
        out.push('\n');
        if !self.fields.is_empty() {
            out.push_str(&format!("\n# {} fields\n", self.fields.len()));
            for f in &self.fields {
                out.push_str(f);
                out.push('\n');
            }
        }
        out.push_str(&format!(
            "\n# outline: the class is {bytes} bytes, over the {budget}-byte output budget. {} methods below; getclass \
             with method=\"name\" (every overload) or a signature for their code, full=true for the whole class\n",
            self.methods.len()
        ));
        for m in &self.methods {
            out.push_str(&format!("{}  # {} insns, {} bytes\n", m.declaration, m.instructions(), m.text.len()));
        }
        out
    }

    /// `name(params)ret` of every method, comma separated, cut to `max` bytes.
    pub fn signatures(&self, max: usize) -> String {
        let mut out = String::new();
        for (i, m) in self.methods.iter().enumerate() {
            if out.len() + m.signature.len() + 2 > max {
                out.push_str(&format!(", ... {} more", self.methods.len() - i));
                break;
            }
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(m.signature);
        }
        out
    }
}

fn is_type_decl(rest: &str) -> bool {
    rest.split_whitespace().any(|w| matches!(w, "class" | "interface" | "enum" | "object"))
}

/// `code` without a trailing `// ...` comment (quotes are respected, so a `//`
/// inside a string stays).
pub(crate) fn strip_line_comment(code: &str) -> &str {
    let bytes = code.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 2;
                    continue;
                }
                if b == q {
                    quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                    return &code[..i];
                }
            }
        }
        i += 1;
    }
    code
}

/// A field / Kotlin property declaration (as opposed to an enum constant,
/// which ends with `,`).
fn is_field_line(code: &str) -> bool {
    let code = code.trim_end();
    if code.ends_with(',') {
        return false;
    }
    if code.ends_with(';') {
        return true;
    }
    code.starts_with("val ") || code.starts_with("var ") || code.starts_with("const ") || code.contains(" val ") || code.contains(" var ")
}

pub(crate) fn source_method_sig(rest: &str) -> Option<&str> {
    // An enum constant with arguments (`FOO(1),`) is not a declaration.
    if rest.trim_end().ends_with(',') {
        return None;
    }
    let open_paren = rest.find('(')?;
    if let Some(eq) = rest.find('=') {
        if eq < open_paren {
            return None;
        }
    }
    let close_paren = rest[open_paren..].find(')')? + open_paren;
    let before = rest[..open_paren].trim_end();
    // Kotlin spells an awkward name in backticks: `fun `in`()`.
    let name_start =
        before.rfind(|c: char| !c.is_alphanumeric() && c != '_' && c != '$' && c != '<' && c != '>' && c != '`').map_or(0, |i| i + 1);
    let name = &before[name_start..];
    if name.is_empty() || matches!(name, "if" | "for" | "while" | "switch" | "catch" | "synchronized") {
        return None;
    }
    // `BAR(2);` — the last enum constant — has no return type or modifiers
    // before the name, unlike an abstract/native method (`void run();`).
    let qualifiers = before[..name_start].trim();
    if qualifiers.is_empty() && rest.trim_end().ends_with(");") {
        return None;
    }
    Some(&rest[name_start..=close_paren])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALI: &str = ".class public LA;\n.super Ljava/lang/Object;\n\n# interfaces\n.implements LI;\n\n\
        # instance fields\n.field private x:I\n\n# direct methods\n.method public constructor <init>()V\n    .registers 1\n    \
        invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n\n# virtual methods\n\
        .method public run(I)V\n    .registers 2\n    :goto_0\n    return-void\n.end method\n\n\
        .method public run(Ljava/lang/String;)V\n    .registers 2\n    return-void\n.end method\n";

    #[test]
    fn splits_header_fields_and_methods() {
        let c = ClassText::parse(SMALI);
        assert!(c.header.ends_with(".implements LI;\n\n"), "{:?}", c.header);
        assert_eq!(c.fields, [".field private x:I"]);
        let sigs: Vec<_> = c.methods.iter().map(|m| m.signature).collect();
        assert_eq!(sigs, ["<init>()V", "run(I)V", "run(Ljava/lang/String;)V"]);
        assert!(c.methods[1].text.starts_with(".method public run(I)V\n") && c.methods[1].text.ends_with(".end method\n"));
    }

    #[test]
    fn selects_by_signature_prefix_or_name() {
        let c = ClassText::parse(SMALI);
        let names = |q: &str| c.select(q).iter().map(|m| m.signature).collect::<Vec<_>>();
        assert_eq!(names("run(I)V"), ["run(I)V"]);
        assert_eq!(names("run"), ["run(I)V", "run(Ljava/lang/String;)V"]);
        assert_eq!(names("run(Ljava"), ["run(Ljava/lang/String;)V"]);
        assert_eq!(names("LA;->run(I)V"), ["run(I)V"]);
        assert!(names("walk").is_empty());
        assert_eq!(c.signatures(1000), "<init>()V, run(I)V, run(Ljava/lang/String;)V");
        assert_eq!(c.signatures(15), "<init>()V, ... 2 more");
    }

    #[test]
    fn outline_lists_methods_with_sizes() {
        let c = ClassText::parse(SMALI);
        let o = c.outline(SMALI.len(), 100);
        assert!(o.contains("# 1 fields\n.field private x:I\n"), "{o}");
        assert!(o.contains(".method public run(I)V  # 1 insns, "), "{o}");
        assert!(o.contains(".method public constructor <init>()V  # 2 insns, "), "{o}");
        assert!(!o.contains("return-void"), "{o}");
    }

    #[test]
    fn kotlin_source_members_survive_comments_companion_and_backticks() {
        let kt = [
            "package x;",
            "",
            "public class A {",
            "    public static int id = 2130903042; // @id/btn",
            "",
            "    companion object {",
            "        public fun `in`(): Unit {",
            "            return Unit.INSTANCE;",
            "        }",
            "    }",
            "",
            "    public fun bar(): Int {",
            "        return 1;",
            "    }",
            "}",
            "",
        ]
        .join("\n");
        let c = ClassText::parse(&kt);
        let sigs: Vec<_> = c.methods.iter().map(|m| m.signature).collect();
        assert_eq!(sigs, ["`in`()", "bar()"], "{sigs:?}");
        // The resource annotation is a comment, not the end of the declaration.
        assert_eq!(c.fields.len(), 1, "{:?}", c.fields);
        assert!(c.fields[0].contains("int id = 2130903042;"), "{:?}", c.fields);
        assert!(c.methods[1].text.ends_with("}\n"), "{:?}", c.methods[1].text);
        assert_eq!(c.select("bar").len(), 1);
        assert_eq!(c.select("`in`").len(), 1);
        // A method's member index maps back to its declaration line.
        let index = crate::output::method_index(&kt);
        assert_eq!(index.len(), 2, "{index:?}");
        let lines: Vec<&str> = kt.lines().collect();
        for (sig, first, last) in &index {
            assert!(lines[first - 1].contains(sig), "{sig}: {}", lines[first - 1]);
            assert_eq!(lines[last - 1].trim(), "}");
        }
    }

    #[test]
    fn enum_constants_with_arguments_are_not_methods() {
        let java = ["public enum E {", "    FOO(1),", "    BAR(2);", "", "    public void run() {", "    }", "}", ""].join("\n");
        let c = ClassText::parse(&java);
        let sigs: Vec<_> = c.methods.iter().map(|m| m.signature).collect();
        assert_eq!(sigs, ["run()"], "{sigs:?}");
    }
}
