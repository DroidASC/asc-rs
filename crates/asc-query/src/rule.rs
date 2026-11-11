//! The rule syntax of `findrefs all` / `rules` and of call graph endpoints,
//! one for both engines.
//!
//! ```text
//! rule  := part ( '&' part )*
//! part  := [ '!' ] KIND ':' value
//! value := [ '=' | '*' ] '{' rule '}' TAIL       a set: kinds of Shape::Set only
//!        | [ '=' | '*' ] '{' '@' PATH '}' TAIL   a set a file lists
//!        | [ '=' | '*' ] '@' PATH                 the same, where the kind allows it bare
//!        | TEXT                                   the kind's own syntax, e.g. a regex
//! ```
//!
//! A `&` joins two parts only where `KIND:` or `!KIND:` follows it (blanks
//! allowed), outside `{}` / `()`: anywhere else it is part of the value,
//! as in record names (`&entry/src/main/ets/pages/Index&`) and regexes. A
//! `\` keeps the next character from joining, opening or closing anything
//! (`string:a\&literal:b` is one regex). TEXT, a PATH and a TAIL run to the
//! next joining `&`, or to the `}` closing the enclosing set; blanks around
//! them do not count.
//!
//! The grammar of an engine ([`Grammar`]) names the kinds and says which
//! take sets; what a value means, a TAIL included, is the engine's to read.

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::path::Path;

/// Sets inside sets deeper than this are a mistake or hostile: each level is
/// another pass over the code, and the parser recurses per level.
pub const MAX_DEPTH: usize = 8;

/// The kinds of one engine.
pub trait Grammar {
    /// A kind, as the engine tells them apart.
    type Kind: Copy;

    /// The kinds, as an error that expects one lists them.
    const KINDS: &'static str;

    /// The kind `word` (the letters before the `:`) names.
    ///
    /// # Errors
    /// What to say about a word that names no kind.
    fn kind(word: &str) -> Result<Self::Kind, String>;

    /// How the value of `kind` is written.
    fn shape(kind: Self::Kind) -> Shape;
}

/// How the value of a kind is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// TEXT only.
    Text,
    /// A set (`{RULE}`, `{@PATH}`) or TEXT; `bare_file`: `@PATH` without
    /// braces is a set too, not TEXT.
    Set { bare_file: bool },
}

/// What a `=` or `*` in front of a set asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Nothing in front.
    Plain,
    /// `=`: the set's own members only.
    Exact,
    /// `*`: everything the set may stand for.
    Every,
}

/// A piece of the rule: its text without the blanks around it, and where
/// it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Text<'a> {
    pub text: &'a str,
    /// Byte offset in the rule.
    pub at: usize,
}

/// A parsed rule: its parts in the order written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule<'a, K> {
    pub parts: Vec<Part<'a, K>>,
}

/// One `[!]KIND:VALUE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part<'a, K> {
    /// Byte offset of the part (its `!`, else its kind) in the rule.
    pub at: usize,
    /// Written with `!`.
    pub negated: bool,
    pub kind: K,
    pub value: Value<'a, K>,
}

/// The value of a part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a, K> {
    Text(Text<'a>),
    Set {
        mode: Mode,
        set: Set<'a, K>,
        /// What follows the set up to the end of the part (empty when nothing).
        tail: Text<'a>,
    },
}

/// The members of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Set<'a, K> {
    /// Those matching a rule.
    Rule(Rule<'a, K>),
    /// Those a file lists.
    File(SetFile<'a>),
}

/// The file of `{@PATH}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetFile<'a> {
    pub path: Text<'a>,
}

impl SetFile<'_> {
    /// The file's text. A relative path is read in `dir` (the current
    /// directory when `None`).
    ///
    /// # Errors
    /// The file does not read as UTF-8 text.
    pub fn read(&self, dir: Option<&Path>) -> io::Result<String> {
        let path = Path::new(self.path.text);
        // An absolute `path` replaces `dir` when joined.
        std::fs::read_to_string(dir.map_or_else(|| path.to_path_buf(), |dir| dir.join(path)))
    }
}

/// A rule that does not parse, or a value its engine does not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    rule: String,
    at: usize,
    message: String,
}

impl SyntaxError {
    /// `message` about `rule` at byte offset `at`.
    pub fn new(rule: &str, at: usize, message: impl Into<String>) -> SyntaxError {
        SyntaxError { rule: rule.to_owned(), at, message: message.into() }
    }

    /// The column, from 1, the error is at.
    pub fn column(&self) -> usize {
        self.at + 1
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad rule {:?}: {} at column {}", self.rule, self.message, self.column())
    }
}

impl std::error::Error for SyntaxError {}

impl<'a, K: Copy> Rule<'a, K> {
    /// Parse `rule` with the kinds of `G`.
    ///
    /// # Errors
    /// A part that is no `KIND:VALUE`, a kind `G` does not have, an empty
    /// value, a set without its `}` or nested deeper than [`MAX_DEPTH`].
    pub fn parse<G: Grammar<Kind = K>>(rule: &'a str) -> Result<Rule<'a, K>, SyntaxError> {
        let mut parser = Parser::<G> { src: rule, pos: 0, depth: 0, grammar: PhantomData };
        let parsed = parser.rule(false)?;
        // At the top a value runs to a joining `&` or the end: nothing is left.
        debug_assert_eq!(parser.peek(), None, "{rule:?}");
        Ok(parsed)
    }
}

/// The parts of `rule` as written, each with its `!`: what stands between
/// the `&` that join them at the top. For a front end that looks at the
/// kinds before an engine parses the rule.
pub fn parts(rule: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = rule;
    loop {
        let len = text_len(rest, false);
        parts.push(rest[..len].trim());
        match rest.get(len + 1..) {
            Some(next) => rest = next,
            None => return parts,
        }
    }
}

struct Parser<'a, G> {
    src: &'a str,
    pos: usize,
    /// Sets open at the cursor.
    depth: usize,
    grammar: PhantomData<G>,
}

impl<'a, G: Grammar> Parser<'a, G> {
    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn skip_blanks(&mut self) {
        self.pos = self.src.len() - self.rest().trim_start().len();
    }

    /// The next non-blank character, not consumed.
    fn peek(&mut self) -> Option<char> {
        self.skip_blanks();
        self.rest().chars().next()
    }

    fn eat(&mut self, c: char) -> bool {
        let found = self.peek() == Some(c);
        if found {
            self.pos += c.len_utf8();
        }
        found
    }

    fn error(&self, message: impl Into<String>) -> SyntaxError {
        SyntaxError::new(self.src, self.pos, message)
    }

    /// `part ('&' part)*`, up to the end or (`nested`) the closing `}`.
    fn rule(&mut self, nested: bool) -> Result<Rule<'a, G::Kind>, SyntaxError> {
        let mut parts = Vec::new();
        loop {
            self.skip_blanks();
            let at = self.pos;
            let negated = self.eat('!');
            parts.push(self.part(at, negated, nested)?);
            // A value ends at a joining `&`, a `}` or the end.
            if !self.eat('&') {
                return Ok(Rule { parts });
            }
        }
    }

    /// `KIND ':' value`, the `!` already eaten.
    fn part(&mut self, at: usize, negated: bool, nested: bool) -> Result<Part<'a, G::Kind>, SyntaxError> {
        self.skip_blanks();
        let rest = self.rest();
        let word = kind_word(rest);
        if word == 0 || !rest[word..].starts_with(':') {
            return Err(self.error(format!("expected KIND:VALUE, KIND one of {}", G::KINDS)));
        }
        let kind = G::kind(&rest[..word]).map_err(|message| self.error(message))?;
        self.pos += word + 1;
        let value = match G::shape(kind) {
            Shape::Text => Value::Text(self.text(nested)?),
            Shape::Set { bare_file } => self.set_or_text(nested, bare_file)?,
        };
        Ok(Part { at, negated, kind, value })
    }

    /// The value of a kind that takes sets.
    fn set_or_text(&mut self, nested: bool, bare_file: bool) -> Result<Value<'a, G::Kind>, SyntaxError> {
        self.skip_blanks();
        let rest = self.rest();
        let (mode, after) = match rest.as_bytes().first() {
            Some(b'=') => (Mode::Exact, &rest[1..]),
            Some(b'*') => (Mode::Every, &rest[1..]),
            _ => (Mode::Plain, rest),
        };
        if after.starts_with('{') {
            self.pos += rest.len() - after.len() + 1;
            if self.depth >= MAX_DEPTH {
                return Err(self.error(format!("bodies are nested deeper than {MAX_DEPTH} levels")));
            }
            self.depth += 1;
            let set = if self.eat('@') { Set::File(SetFile { path: self.text(true)? }) } else { Set::Rule(self.rule(true)?) };
            self.depth -= 1;
            if !self.eat('}') {
                return Err(self.error("expected `}`"));
            }
            return Ok(Value::Set { mode, set, tail: self.tail(nested) });
        }
        if bare_file && after.starts_with('@') {
            self.pos += rest.len() - after.len() + 1;
            let path = self.text(nested)?;
            return Ok(Value::Set { mode, set: Set::File(SetFile { path }), tail: Text { text: "", at: self.pos } });
        }
        Ok(Value::Text(self.text(nested)?))
    }

    /// TEXT at the cursor; an error when there is none.
    fn text(&mut self, nested: bool) -> Result<Text<'a>, SyntaxError> {
        let text = self.tail(nested);
        if text.text.is_empty() {
            return Err(self.error("empty value"));
        }
        Ok(text)
    }

    /// TEXT at the cursor, maybe none.
    fn tail(&mut self, nested: bool) -> Text<'a> {
        self.skip_blanks();
        let at = self.pos;
        let len = text_len(self.rest(), nested);
        self.pos += len;
        Text { text: self.src[at..self.pos].trim_end(), at }
    }
}

/// Bytes of the ASCII letters at the start of `s`.
fn kind_word(s: &str) -> usize {
    s.find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(s.len())
}

/// Whether a `&` followed by `rest` joins two parts: `KIND:` or `!KIND:`
/// comes next.
fn joins(rest: &str) -> bool {
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('!').unwrap_or(rest).trim_start();
    let word = kind_word(rest);
    word > 0 && rest[word..].starts_with(':')
}

/// Bytes of TEXT at the start of `s`: up to a joining `&` outside `{}` /
/// `()`, or an unmatched `}` when `nested`. A `\` keeps the next character in.
fn text_len(s: &str, nested: bool) -> usize {
    let mut depth = 0usize;
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '{' | '(' => depth += 1,
            '}' | ')' if depth > 0 => depth -= 1,
            '}' if nested => return i,
            '&' if depth == 0 && joins(&s[i + 1..]) => return i,
            _ => {}
        }
    }
    s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A grammar of three kinds: `text:` TEXT, `set:` a set, `bare:` a set
    /// that also takes `@PATH`.
    struct Test;

    impl Grammar for Test {
        type Kind = &'static str;
        const KINDS: &'static str = "text, set, bare";

        fn kind(word: &str) -> Result<&'static str, String> {
            ["text", "set", "bare"].into_iter().find(|kind| *kind == word).ok_or_else(|| format!("unknown kind {word:?}"))
        }

        fn shape(kind: &'static str) -> Shape {
            match kind {
                "text" => Shape::Text,
                "set" => Shape::Set { bare_file: false },
                _ => Shape::Set { bare_file: true },
            }
        }
    }

    /// The rule as a compact string: `!kind:'text'`, `kind:={...}+'tail'`, `@'path'`.
    fn shape(rule: &str) -> String {
        fn of(rule: &Rule<'_, &str>) -> String {
            let parts = rule.parts.iter().map(|part| {
                let value = match &part.value {
                    Value::Text(text) => format!("'{}'", text.text),
                    Value::Set { mode, set, tail } => {
                        let mode = match mode {
                            Mode::Plain => "",
                            Mode::Exact => "=",
                            Mode::Every => "*",
                        };
                        let set = match set {
                            Set::Rule(rule) => format!("{{{}}}", of(rule)),
                            Set::File(file) => format!("@'{}'", file.path.text),
                        };
                        if tail.text.is_empty() { format!("{mode}{set}") } else { format!("{mode}{set}+'{}'", tail.text) }
                    }
                };
                format!("{}{}:{value}", if part.negated { "!" } else { "" }, part.kind)
            });
            parts.collect::<Vec<_>>().join(" & ")
        }
        match Rule::parse::<Test>(rule) {
            Ok(parsed) => of(&parsed),
            Err(e) => format!("error: {e}"),
        }
    }

    #[test]
    fn an_ampersand_joins_only_ahead_of_a_kind() {
        assert_eq!(shape("text:a & !text:b&text:c"), "text:'a' & !text:'b' & text:'c'");
        assert_eq!(shape("text:a&b"), "text:'a&b'");
        assert_eq!(shape("text:&a/b&->f & text:N&&&a/b&#x"), "text:'&a/b&->f' & text:'N&&&a/b&#x'");
        assert_eq!(shape(r"text:a\&text:b"), r"text:'a\&text:b'");
        assert_eq!(shape("text:a&! text:b"), "text:'a' & !text:'b'");
        // Inside brackets a `&` is part of the value; a `\` keeps a bracket from counting.
        assert_eq!(shape("text:(a&text:b) & text:c"), "text:'(a&text:b)' & text:'c'");
        assert_eq!(shape(r"text:a\{ & text:b"), r"text:'a\{' & text:'b'");
        assert_eq!(shape("text:^a{2,3}$ & text:b"), "text:'^a{2,3}$' & text:'b'");
        // A dangling `&` is part of the value.
        assert_eq!(shape("text:a & "), "text:'a &'");
        assert_eq!(parts("set:{text:a & text:b} & !text:c"), ["set:{text:a & text:b}", "!text:c"]);
        assert_eq!(parts("text:a&b"), ["text:a&b"]);
        assert_eq!(parts("text:a & !text:b"), ["text:a", "!text:b"]);
    }

    #[test]
    fn sets_nest_rules_and_files() {
        assert_eq!(shape("set:{text:a & !text:b} & text:c"), "set:{text:'a' & !text:'b'} & text:'c'");
        assert_eq!(shape("set:={set:*{text:a}}"), "set:={set:*{text:'a'}}");
        assert_eq!(shape("set:{ @ dir/list.txt }"), "set:@'dir/list.txt'");
        assert_eq!(shape("set:{text:a}[x=1] & text:b"), "set:{text:'a'}+'[x=1]' & text:'b'");
        // `@` and `=` start no set by themselves where the kind does not say so.
        assert_eq!(shape("set:@ohos:net"), "set:'@ohos:net'");
        assert_eq!(shape("set:=name"), "set:'=name'");
        assert_eq!(shape("bare:=@list.txt"), "bare:=@'list.txt'");
        assert_eq!(shape("bare:@list.txt[x=1] & text:a"), "bare:@'list.txt[x=1]' & text:'a'");
        // Braces only open a set at the start of the value, and only for kinds with sets.
        assert_eq!(shape("text:{a}"), "text:'{a}'");
        assert_eq!(shape("set:a{2}"), "set:'a{2}'");
        // A regex brace inside a set stays in its value.
        assert_eq!(shape("set:{text:a{2}}"), "set:{text:'a{2}'}");
        // An unmatched `}` closes a set; at the top it is text.
        assert_eq!(shape("set:{text:a}b}"), "set:{text:'a'}+'b}'");
        assert_eq!(shape("text:a}"), "text:'a}'");
    }

    #[test]
    fn errors_say_what_and_where() {
        for (rule, message) in [
            ("bogus", "bad rule \"bogus\": expected KIND:VALUE, KIND one of text, set, bare at column 1"),
            ("text:a & other:b", "bad rule \"text:a & other:b\": unknown kind \"other\" at column 10"),
            ("text:", "bad rule \"text:\": empty value at column 6"),
            ("set:{text:a", "bad rule \"set:{text:a\": expected `}` at column 12"),
            ("set:{@}", "bad rule \"set:{@}\": empty value at column 7"),
        ] {
            assert_eq!(shape(rule), format!("error: {message}"), "{rule}");
        }
        let e = Rule::parse::<Test>("text:").unwrap_err();
        assert_eq!((e.column(), e.message()), (6, "empty value"));
    }

    #[test]
    fn sets_nest_up_to_the_limit() {
        let nest = |n: usize| format!("{}text:a{}", "set:{".repeat(n), "}".repeat(n));
        assert!(Rule::parse::<Test>(&nest(MAX_DEPTH)).is_ok());
        // Far past the limit is an error, not a stack overflow.
        for n in [MAX_DEPTH + 1, 100_000] {
            assert!(shape(&nest(n)).contains(&format!("nested deeper than {MAX_DEPTH} levels")), "{n}");
        }
        // Siblings do not add up.
        let wide = vec![nest(MAX_DEPTH); 50].join(" & ");
        assert!(Rule::parse::<Test>(&wide).is_ok());
    }

    #[test]
    fn a_set_file_reads_relative_to_its_directory() {
        let dir = std::env::temp_dir();
        let name = format!("asc-query-set-{}.txt", std::process::id());
        std::fs::write(dir.join(&name), "La;->m()V\n").unwrap();
        let rule = format!("set:{{@{name}}}");
        let parsed = Rule::parse::<Test>(&rule).unwrap();
        let Value::Set { set: Set::File(file), .. } = &parsed.parts[0].value else { panic!("a file set") };
        assert_eq!(file.read(Some(&dir)).unwrap(), "La;->m()V\n");
        assert!(file.read(Some(Path::new("/nonexistent"))).is_err());
        std::fs::remove_file(dir.join(&name)).unwrap();
    }
}
