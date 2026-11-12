//! Decompiled source as asc handles it after the backend: the methods
//! `--method` picks, and the file `-o` writes it to.
//!
//! Picking works on the text alone (§6.3: without `lines`, asc matches
//! source by method name): a declaration is a line naming the method right
//! after a type or modifier (or `fun`), and its body runs to the brace that
//! closes the one it opens, string literals and comments skipped. Comments
//! and annotations right above the declaration go with it.

use std::path::PathBuf;

/// The name a method query stands for in source: the name before `(`,
/// without an owner (`Lcls;->`); a constructor is named after its class.
fn source_name<'a>(query: &'a str, simple_class: &'a str) -> &'a str {
    let member = query.rsplit_once("->").map_or(query, |(_, member)| member).trim();
    let name = member.split('(').next().unwrap_or(member).trim();
    if name == "<init>" { simple_class } else { name }
}

/// The class's simple name as source spells it: after the last `/`, `$` and `.`.
pub(super) fn simple_name(descriptor: &str) -> &str {
    let inner = descriptor.strip_prefix('L').and_then(|d| d.strip_suffix(';')).unwrap_or(descriptor);
    inner.rsplit(['/', '$', '.']).next().unwrap_or(inner)
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '$'
}

/// What may stand right before a declared method's name: the return type
/// (`int`, `List<String>`, `byte[]`) or a modifier; never an operator, a
/// call or a keyword that starts a statement.
fn declares(before: &str) -> bool {
    const STATEMENTS: &[&str] = &["return", "new", "throw", "else", "case", "yield", "await", "if", "while", "for", "switch"];
    let before = before.trim_end();
    let Some(last) = before.split_whitespace().last() else { return false };
    let last_word = last.trim_start_matches(|c: char| !is_ident(c));
    if STATEMENTS.contains(&last_word) || before.starts_with("return ") {
        return false;
    }
    last.ends_with(|c: char| is_ident(c) || c == '>' || c == ']')
}

/// Whether line `line` declares `name`: `static {` for a static initialiser,
/// else `name(` after a type, a modifier, `fun` or (a constructor) nothing.
fn is_declaration(line: &str, name: &str, constructor: bool) -> bool {
    let trimmed = line.trim();
    if name == "<clinit>" {
        return trimmed.starts_with("static {") || trimmed == "static" || trimmed.starts_with("init {");
    }
    if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") || trimmed.starts_with('@') {
        return false;
    }
    let call = format!("{name}(");
    let mut from = 0;
    while let Some(at) = trimmed[from..].find(&call).map(|i| from + i) {
        from = at + call.len();
        if trimmed[..at].ends_with(is_ident) || trimmed[..at].trim_end().ends_with('.') {
            continue;
        }
        let before = &trimmed[..at];
        if before.split_whitespace().any(|word| word == "fun") || declares(before) {
            return true;
        }
        if constructor && before.split_whitespace().all(|word| ["public", "protected", "private", "constructor"].contains(&word)) {
            return true;
        }
    }
    false
}

/// Index just past the brace closing the first `{` at or after `from`, or
/// past the first `;` if a `;` comes first (a declaration without a body);
/// `None` if neither comes.
fn block_end(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i = text[i + 2..].find("*/").map_or(bytes.len(), |end| i + 2 + end + 1);
            }
            b';' if depth == 0 => return Some(i + 1),
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The methods `query` names in `source`, each with the comments and
/// annotations right above it, separated by a blank line; `None` if no
/// declaration matches.
pub(super) fn pick_methods(source: &str, query: &str, descriptor: &str) -> Option<String> {
    let simple = simple_name(descriptor);
    let constructor = query.contains("<init>") || source_name(query, simple) == simple;
    let name = if query.contains("<clinit>") { "<clinit>" } else { source_name(query, simple) };
    let lines: Vec<(usize, &str)> = source
        .split_inclusive('\n')
        .scan(0, |offset, line| {
            let start = *offset;
            *offset += line.len();
            Some((start, line))
        })
        .collect();
    let mut picked: Vec<&str> = Vec::new();
    let mut resume = 0;
    for (index, &(start, line)) in lines.iter().enumerate() {
        if start < resume || !is_declaration(line, name, constructor) {
            continue;
        }
        let Some(end) = block_end(source, start) else { continue };
        let mut first = index;
        while first > 0 {
            let above = lines[first - 1].1.trim();
            let attached = above.starts_with('@') || above.starts_with("//") || above.starts_with("/*") || above.starts_with('*');
            if !attached {
                break;
            }
            first -= 1;
        }
        let end = source[end..].find('\n').map_or(source.len(), |nl| end + nl + 1);
        picked.push(source[lines[first].0..end].trim_end_matches('\n'));
        resume = end;
    }
    (!picked.is_empty()).then(|| picked.iter().map(|text| format!("{text}\n")).collect::<Vec<_>>().join("\n"))
}

/// The declaration of the nested class `descriptor` in `source`, the
/// source of a class it is folded into: from the line declaring a type of
/// its simple name to the brace closing it. `None` when no line declares it
/// (an anonymous class, a name the source escaped).
pub(super) fn nested_block<'a>(source: &'a str, descriptor: &str) -> Option<&'a str> {
    const TYPES: &[&str] = &["class", "interface", "enum", "record", "object", "@interface"];
    let simple = simple_name(descriptor);
    let mut start = 0;
    for line in source.split_inclusive('\n') {
        let comment = ["//", "/*", "*"].iter().any(|marker| line.trim_start().starts_with(marker));
        let mut words =
            line.split(|c: char| !(is_ident(c) || c == '@')).filter(|word| !word.is_empty()).skip_while(|word| !TYPES.contains(word));
        if !comment && words.next().is_some() && words.next() == Some(simple) {
            let end = block_end(source, start)?;
            return Some(&source[start..end]);
        }
        start += line.len();
    }
    None
}

/// Where `-o DIR` writes the class `descriptor` (already renamed when the
/// backend applied a mapping): its package as directories, its binary name
/// with `extension`. Built from the descriptor alone, for when the backend's
/// `path` is missing or unsafe (`backend_path`, §11); segments that would
/// leave the directory are replaced.
pub fn output_path(descriptor: &str, extension: &str) -> PathBuf {
    let inner = descriptor.strip_prefix('L').and_then(|d| d.strip_suffix(';')).unwrap_or(descriptor);
    let mut segments: Vec<String> = inner
        .split('/')
        .map(|segment| {
            let clean: String = segment.chars().map(|c| if c == '\\' || c == '\0' || c.is_control() { '_' } else { c }).collect();
            if clean.is_empty() || clean == "." || clean == ".." { clean.replace('.', "_") + "_" } else { clean }
        })
        .collect();
    if let Some(last) = segments.last_mut() {
        last.push('.');
        last.push_str(extension);
    }
    segments.iter().collect()
}

/// The backend's own `path` for a unit, when `-o DIR` can write it as is:
/// relative, every segment a plain name (no `.`, `..`, root, separators or
/// control characters), ending in `.extension`. A backend knows how it
/// escaped names the source cannot spell (`Main-IA` declares `MainIA`), so
/// its path matches the class the file declares; anything else gives `None`
/// and the caller falls back to [`output_path`] (§11).
pub(super) fn backend_path(path: &str, extension: &str) -> Option<PathBuf> {
    let segments: Vec<&str> = path.split('/').collect();
    let plain = |segment: &&str| {
        !segment.is_empty()
            && *segment != "."
            && *segment != ".."
            && !segment.chars().any(|c| c == '\\' || c == ':' || c == '\0' || c.is_control())
    };
    let file = segments.last()?.strip_suffix(extension)?.strip_suffix('.')?;
    (segments.iter().all(plain) && !file.is_empty()).then(|| segments.iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const JAVA: &str = r#"package a.b;

import java.util.List;

public class Main extends Base {
    private int count;

    public Main(int count) {
        this.count = count;
    }

    static {
        System.loadLibrary("x");
    }

    /** Runs. */
    @Override
    public void run(int n) {
        String s = "run(1) { not a block";
        if (n > 0) {
            run(n - 1);
        }
    }

    public List<String> run(String s) {
        return helper.run(s);
    }

    abstract int size();

    int total() {
        return size() + count; // size() is called here
    }
}
"#;

    #[test]
    fn finds_the_declaration_of_a_nested_class() {
        let source = "public class Outer {\n    void touch() {}\n\n    // class Inner is below\n    static class Inner<T> extends Outer {\n        void touch() { String s = \"}\"; }\n    }\n\n    enum Kind { A }\n}\n";
        let inner = nested_block(source, "La/Outer$Inner;").unwrap();
        assert!(inner.starts_with("    static class Inner<T>") && inner.ends_with("}\n    }"), "{inner:?}");
        assert_eq!(pick_methods(inner, "touch", "La/Outer$Inner;").unwrap(), "        void touch() { String s = \"}\"; }\n");
        assert_eq!(nested_block(source, "La/Outer$Kind;"), Some("    enum Kind { A }"));
        assert_eq!(nested_block(source, "La/Outer$1;"), None);
    }

    #[test]
    fn picks_every_overload_with_what_is_attached_above() {
        let run = pick_methods(JAVA, "run", "La/b/Main;").unwrap();
        assert!(run.starts_with("    /** Runs. */\n    @Override\n    public void run(int n) {\n"), "{run}");
        assert!(run.contains("            run(n - 1);\n        }\n    }\n\n    public List<String> run(String s) {"), "{run}");
        assert!(run.ends_with("        return helper.run(s);\n    }\n"), "{run}");
        assert!(!run.contains("total"), "{run}");
        let by_signature = pick_methods(JAVA, "La/b/Main;->run(I)V", "La/b/Main;").unwrap();
        assert!(by_signature.contains("public void run(int n)"), "{by_signature}");
    }

    #[test]
    fn picks_constructors_initialisers_and_bodiless_methods() {
        let init = pick_methods(JAVA, "<init>(I)V", "La/b/Main;").unwrap();
        assert_eq!(init, "    public Main(int count) {\n        this.count = count;\n    }\n");
        let clinit = pick_methods(JAVA, "<clinit>", "La/b/Main;").unwrap();
        assert_eq!(clinit, "    static {\n        System.loadLibrary(\"x\");\n    }\n");
        assert_eq!(pick_methods(JAVA, "size", "La/b/Main;").unwrap(), "    abstract int size();\n", "calls are not declarations");
        assert!(pick_methods(JAVA, "walk", "La/b/Main;").is_none());
    }

    #[test]
    fn picks_kotlin_functions() {
        let kotlin =
            "class Main {\n    fun run(n: Int): Int {\n        return run(n - 1)\n    }\n\n    private suspend fun stop() = Unit\n}\n";
        assert_eq!(pick_methods(kotlin, "run", "LMain;").unwrap(), "    fun run(n: Int): Int {\n        return run(n - 1)\n    }\n");
    }

    #[test]
    fn output_paths_come_from_the_descriptor_and_stay_inside() {
        assert_eq!(output_path("Lbin/mt/json/JSONObject$Member;", "java"), Path::new("bin/mt/json/JSONObject$Member.java"));
        assert_eq!(output_path("LTop;", "kt"), Path::new("Top.kt"));
        assert_eq!(output_path("L../x/./y;", "java"), Path::new("___/x/__/y.java"));
        assert!(output_path("L../../etc/passwd;", "smali").components().all(|c| matches!(c, std::path::Component::Normal(_))));
        assert_eq!(simple_name("La/b/Outer$Inner;"), "Inner");
    }

    #[test]
    fn backend_paths_are_taken_only_when_they_stay_inside() {
        assert_eq!(backend_path("a/b/MainIA.java", "java"), Some(PathBuf::from("a/b/MainIA.java")));
        assert_eq!(backend_path("Top.kt", "kt"), Some(PathBuf::from("Top.kt")));
        for bad in ["", "/etc/x.java", "a/../x.java", "./x.java", "a//x.java", "a\\x.java", "C:x.java", "x.kt", ".java", "a/.java"] {
            assert_eq!(backend_path(bad, "java"), None, "{bad}");
        }
    }
}
