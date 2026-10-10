//! Editor tabs: one per opened class or manifest, with in-tab find and the
//! line-level parsing behind the source context menu (member spans live in
//! [`crate::members`]). Pure logic, no egui.

use crate::members::{declaration, declaration_line, MemberKind};

/// Where to scroll once a class tab has its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jump {
    /// The first `.method` named so (search results carry no prototype).
    Method(String),
    /// One exact declaration: kind, name and prototype / field type.
    Member { kind: MemberKind, name: String, descriptor: String },
}

/// What a tab currently shows.
pub enum TabContent {
    /// Extraction in progress.
    Loading,
    /// Extraction failed; the tab stays open so the error is not lost.
    Error(String),
    /// Disassembly or XML, one entry per line.
    Text(Vec<String>),
}

pub struct Tab {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub content: TabContent,
    /// Id of the extraction request this tab is waiting for (or last got).
    /// Replies carrying another id belong to a closed incarnation of the tab.
    pub req: u64,
    /// Lower-cased copy of the text lines for case-insensitive find.
    lower: Vec<String>,
    pub find: String,
    /// Sorted line indexes matching `find`.
    pub find_matches: Vec<usize>,
    pub find_cursor: usize,
    /// Line to scroll into view on the next frame.
    pub scroll_to: Option<usize>,
    /// Line highlighted as the navigation target (e.g. a method opened from a
    /// search result).
    pub jump_line: Option<usize>,
    /// Declaration to jump to once the text arrives.
    pub pending_jump: Option<Jump>,
    /// `(line, byte column)` last clicked: the "cursor" of the read-only view.
    pub caret: Option<(usize, usize)>,
}

impl Tab {
    pub fn loading(id: String, title: String, subtitle: String) -> Tab {
        Tab {
            id,
            title,
            subtitle,
            content: TabContent::Loading,
            req: 0,
            lower: Vec::new(),
            find: String::new(),
            find_matches: Vec::new(),
            find_cursor: 0,
            scroll_to: None,
            jump_line: None,
            pending_jump: None,
            caret: None,
        }
    }

    pub fn is_loading(&self) -> bool {
        matches!(self.content, TabContent::Loading)
    }

    /// Whether an extraction reply for `descriptor` with request id `req`
    /// belongs to this tab. A tab closed while loading and reopened gets a
    /// new id, so the reply to the first request is dropped as stale.
    pub fn accepts(&self, descriptor: &str, req: u64) -> bool {
        self.id == descriptor && self.req == req
    }

    pub fn is_error(&self) -> bool {
        matches!(self.content, TabContent::Error(_))
    }

    pub fn lines(&self) -> &[String] {
        match &self.content {
            TabContent::Text(lines) => lines,
            _ => &[],
        }
    }

    /// Replace the content with `text`; re-applies an active find and any
    /// pending jump. Returns the pending jump if its target is not declared
    /// in the new text.
    pub fn set_text(&mut self, text: &str) -> Option<Jump> {
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        self.lower = lines.iter().map(|l| l.to_lowercase()).collect();
        self.content = TabContent::Text(lines);
        self.jump_line = None;
        self.scroll_to = None;
        self.caret = None;
        self.refresh_find();
        let jump = self.pending_jump.take()?;
        if self.jump_to(&jump) {
            None
        } else {
            Some(jump)
        }
    }

    pub fn set_error(&mut self, error: String) {
        self.content = TabContent::Error(error);
        self.clear_text_state();
    }

    pub fn set_loading(&mut self) {
        self.content = TabContent::Loading;
        self.clear_text_state();
    }

    fn clear_text_state(&mut self) {
        self.caret = None;
        self.lower = Vec::new();
        self.find_matches.clear();
        self.find_cursor = 0;
    }

    /// Whether line `i` matches the active find (O(log n): matches are sorted).
    pub fn is_find_match(&self, i: usize) -> bool {
        self.find_matches.binary_search(&i).is_ok()
    }

    /// Recompute the find matches (case-insensitive substring) and scroll to
    /// the first one.
    pub fn refresh_find(&mut self) {
        self.find_matches.clear();
        self.find_cursor = 0;
        if self.find.is_empty() {
            return;
        }
        let kw = self.find.to_lowercase();
        self.find_matches = self.lower.iter().enumerate().filter(|(_, l)| l.contains(&kw)).map(|(i, _)| i).collect();
        if let Some(&first) = self.find_matches.first() {
            self.scroll_to = Some(first);
        }
    }

    pub fn step_find(&mut self, backwards: bool) {
        if self.find_matches.is_empty() {
            return;
        }
        let n = self.find_matches.len();
        self.find_cursor = if backwards { (self.find_cursor + n - 1) % n } else { (self.find_cursor + 1) % n };
        self.scroll_to = Some(self.find_matches[self.find_cursor]);
    }

    /// Scroll to and highlight the declaration `jump` names, with the caret
    /// on its name (so `X` right after a jump finds its references). Returns
    /// false when it is not in this class (e.g. inherited).
    pub fn jump_to(&mut self, jump: &Jump) -> bool {
        let line = match jump {
            Jump::Method(name) => method_line(self.lines(), name),
            Jump::Member { kind, name, descriptor } => declaration_line(self.lines(), &self.id, *kind, name, Some(descriptor)),
        };
        match line {
            Some(i) => {
                self.jump_line = Some(i);
                self.scroll_to = Some(i);
                self.caret = declaration(&self.lines()[i], &self.id).map(|d| (i, d.start));
                true
            }
            None => false,
        }
    }
}

/// The active index after removing item `removed` from a list now `len` long.
pub fn active_after_close(active: usize, removed: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else if active > removed || active >= len {
        active.saturating_sub(1).min(len - 1)
    } else {
        active
    }
}

/// Index of the `.method` line declaring `name`.
pub fn method_line(lines: &[String], name: &str) -> Option<usize> {
    let needle = format!(" {name}(");
    lines.iter().position(|l| {
        let t = l.trim_start();
        t.starts_with(".method ") && t.contains(&needle)
    })
}

fn is_descriptor_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'/' | b'-')
}

/// Every distinct class descriptor (`Lpkg/Cls;`) mentioned on a line, in order.
pub fn descriptors_in_line(line: &str) -> Vec<String> {
    let b = line.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let starts_token = i == 0 || !is_descriptor_byte(b[i - 1]);
        if b[i] == b'L' && starts_token {
            let mut j = i + 1;
            while j < b.len() && is_descriptor_byte(b[j]) {
                j += 1;
            }
            if j > i + 1 && j < b.len() && b[j] == b';' {
                let d = &line[i..=j];
                if !out.iter().any(|x| x == d) {
                    out.push(d.to_string());
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// The literal of a `const-string` line, unescaped.
pub fn const_string_in_line(line: &str) -> Option<String> {
    let t = line.trim_start();
    if !t.starts_with("const-string") {
        return None;
    }
    let start = t.find('"')?;
    let end = t.rfind('"')?;
    if end <= start {
        return None;
    }
    Some(smali_unescape(&t[start + 1..end]))
}

/// Undo the escapes the disassembler applies to string literals.
pub fn smali_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push_str("\\u");
                        out.push_str(&hex);
                    }
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Escape `s` so it matches literally inside a search regex.
pub fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(c, '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '#' | '&' | '-' | '~') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `Cls` from `Lpkg/Cls;` (`LLoader` from `Lpkg/LLoader;`: only the
/// descriptor's leading `L` is syntax, see [`asc_engine::names::class_inner`]).
pub fn short_name(descriptor: &str) -> String {
    let inner = asc_engine::names::class_inner(descriptor);
    inner.rsplit('/').next().unwrap_or(inner).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<String> {
        s.lines().map(str::to_string).collect()
    }

    #[test]
    fn find_steps_and_wraps() {
        let mut tab = Tab::loading("a".into(), "a".into(), "a".into());
        tab.set_text("foo\nbar\nFoo\nbaz");
        tab.find = "foo".into();
        tab.refresh_find();
        assert_eq!(tab.find_matches, vec![0, 2]);
        assert_eq!(tab.scroll_to, Some(0));
        tab.step_find(false);
        assert_eq!(tab.scroll_to, Some(2));
        tab.step_find(false);
        assert_eq!(tab.scroll_to, Some(0));
        tab.step_find(true);
        assert_eq!(tab.scroll_to, Some(2));
        assert!(tab.is_find_match(0) && !tab.is_find_match(1) && tab.is_find_match(2));
        tab.set_loading();
        assert!(tab.find_matches.is_empty() && !tab.is_find_match(0));
        tab.set_text("FOO");
        assert_eq!(tab.find_matches, vec![0]);
    }

    #[test]
    fn stale_class_replies_are_rejected() {
        // First incarnation of the tab asked with request 1, was closed, and
        // the reopened tab asked with request 2.
        let mut tab = Tab::loading("Lx;".into(), "x".into(), "Lx;".into());
        tab.req = 2;
        assert!(!tab.accepts("Lx;", 1));
        assert!(tab.accepts("Lx;", 2));
        assert!(!tab.accepts("Ly;", 2));
    }

    #[test]
    fn active_index_survives_closing() {
        // closing before the active one shifts it left
        assert_eq!(active_after_close(3, 1, 4), 2);
        // closing after it leaves it alone
        assert_eq!(active_after_close(1, 3, 4), 1);
        // closing the active one keeps the same slot unless it was last
        assert_eq!(active_after_close(1, 1, 3), 1);
        assert_eq!(active_after_close(3, 3, 3), 2);
        assert_eq!(active_after_close(0, 0, 0), 0);
    }

    #[test]
    fn pending_jump_applies_when_text_arrives() {
        let mut tab = Tab::loading("a".into(), "a".into(), "a".into());
        tab.pending_jump = Some(Jump::Method("onCreate".into()));
        let unresolved = tab.set_text(".class Lx;\n.method public onCreate(Landroid/os/Bundle;)V\n    return-void\n.end method");
        assert_eq!(unresolved, None);
        assert_eq!(tab.jump_line, Some(1));
        assert_eq!(tab.scroll_to, Some(1));
        assert!(tab.pending_jump.is_none());
        assert!(!tab.jump_to(&Jump::Method("missing".into())));
        tab.pending_jump = Some(Jump::Method("missing".into()));
        assert_eq!(tab.set_text(".class Lx;"), Some(Jump::Method("missing".into())));
    }

    #[test]
    fn member_jump_picks_the_overload_and_places_the_caret() {
        let mut tab = Tab::loading("Lx;".into(), "x".into(), "Lx;".into());
        let text = ".class Lx;\n.field f:I\n.method run()V\n.end method\n.method public run(I)V\n.end method";
        tab.pending_jump = Some(Jump::Member { kind: MemberKind::Method, name: "run".into(), descriptor: "(I)V".into() });
        assert_eq!(tab.set_text(text), None);
        assert_eq!((tab.jump_line, tab.caret), (Some(4), Some((4, ".method public ".len()))));
        tab.caret = Some((2, 3));
        assert!(tab.jump_to(&Jump::Member { kind: MemberKind::Field, name: "f".into(), descriptor: "I".into() }));
        assert_eq!((tab.jump_line, tab.caret), (Some(1), Some((1, ".field ".len()))));
        // The caret lands on the declaration, so `X` finds this member.
        let (line, col) = tab.caret.unwrap();
        let m = crate::members::member_at(&tab.lines()[line], &tab.id, col).unwrap();
        assert_eq!((m.kind, m.name.as_str(), m.declaration), (MemberKind::Field, "f", true));
        let missing = Jump::Member { kind: MemberKind::Field, name: "f".into(), descriptor: "J".into() };
        assert!(!tab.jump_to(&missing));
        assert_eq!(tab.caret, Some((1, ".field ".len())));
        tab.pending_jump = Some(missing.clone());
        assert_eq!(tab.set_text(text), Some(missing));
        tab.caret = Some((0, 0));
        tab.set_loading();
        assert_eq!(tab.caret, None);
    }

    #[test]
    fn method_line_matches_constructors() {
        let l = lines(".method public constructor <init>()V\n.method static foo(I)V");
        assert_eq!(method_line(&l, "<init>"), Some(0));
        assert_eq!(method_line(&l, "foo"), Some(1));
        assert_eq!(method_line(&l, "fo"), None);
    }

    #[test]
    fn descriptors_are_extracted_once_each() {
        let d = descriptors_in_line("    invoke-virtual {p0, v1}, Lcom/x/Y$Z;->run([Ljava/lang/String;Lcom/x/Y$Z;)Ljava/lang/Long;");
        assert_eq!(d, vec!["Lcom/x/Y$Z;", "Ljava/lang/String;", "Ljava/lang/Long;"]);
        assert!(descriptors_in_line("    const/4 v0, 0x1").is_empty());
        assert_eq!(descriptors_in_line(".class public LMain;"), vec!["LMain;"]);
    }

    #[test]
    fn const_string_is_unescaped() {
        assert_eq!(const_string_in_line("    const-string v0, \"a\\\"b\\n\\u0041\"").as_deref(), Some("a\"b\nA"));
        assert_eq!(const_string_in_line("    const/4 v0, 0x1"), None);
    }

    #[test]
    fn regex_escape_makes_literal() {
        assert_eq!(regex_escape("Lcom/x/Y$Z;"), "Lcom/x/Y\\$Z;");
        assert_eq!(regex_escape("a.b(c)"), "a\\.b\\(c\\)");
    }
}
