//! The code around a reference (`findrefs --context`): the listing of the
//! function as `getclass` prints it, cut to the lines around the matched
//! instructions. The block has the shape of the DEX side's:
//!
//! ```text
//! ets/modules.abc | &entry/src/main/ets/pages/Index&->#~@0>#load+0x12 | Index.load | lda.str "https://…"
//!   @ pc 0x12 line 34
//!       000e  lda v2
//!   >   0012  lda.str "https://…"
//!       0015  sta v4
//! ```
//!
//! An `@` line with the code offset and source line of each site, then the
//! listing, `>` in front of the matched instructions and `--` between
//! windows that do not touch. Labels, try ranges and the header of the
//! function are lines of the listing like any other.

use asc_abc::{Abc, Method};

use super::{RefRow, RefSite};
use crate::disasm;

/// How much code to return with each `findrefs` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefContext {
    /// The row alone.
    #[default]
    None,
    /// The matched instructions with this many lines of the listing around each.
    Lines(usize),
    /// The whole function.
    Method,
}

/// Most lines one row's context shows; beyond it the rest is summarised.
const CONTEXT_MAX_LINES: usize = 150;
/// A whole function longer than [`CONTEXT_MAX_LINES`] shows this many lines
/// around each reference instead.
const METHOD_FALLBACK_LINES: usize = 10;

/// The code offset an instruction line of a listing starts with:
/// `  0012  lda.str "x"`.
fn line_pc(line: &str) -> Option<u32> {
    let rest = line.strip_prefix("  ")?;
    let (digits, _) = rest.split_once("  ")?;
    (digits.len() >= 4 && digits.bytes().all(|b| b.is_ascii_hexdigit())).then(|| u32::from_str_radix(digits, 16).ok())?
}

/// The source line of the instruction at `pc`, when the debug info has one.
fn source_line(method: &Method<'_>, pc: u32) -> Option<u32> {
    let info = method.debug_info().ok()??;
    let mut line = info.line_start;
    for row in info.line_rows().ok()? {
        let row = row.ok()?;
        if row.pc > pc {
            break;
        }
        line = row.line;
    }
    // Compiler-generated code carries line -1.
    i32::try_from(line).is_ok().then_some(line)
}

/// The windows of `around` lines about each of `hits` (sorted line
/// indexes) in a listing of `len` lines, merged where they touch.
fn windows(hits: &[usize], around: usize, len: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for &hit in hits {
        let (start, end) = (hit.saturating_sub(around), (hit + around + 1).min(len));
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// What a context block is made from.
struct Listing<'t> {
    lines: Vec<&'t str>,
    /// Line index of each instruction, by code offset, in code order.
    by_pc: Vec<(u32, usize)>,
}

impl<'t> Listing<'t> {
    fn of(text: &'t str) -> Listing<'t> {
        let lines: Vec<&str> = text.lines().collect();
        let by_pc = lines.iter().enumerate().filter_map(|(index, line)| Some((line_pc(line)?, index))).collect();
        Listing { lines, by_pc }
    }

    fn line_of(&self, pc: u32) -> Option<usize> {
        self.by_pc.binary_search_by_key(&pc, |&(pc, _)| pc).ok().map(|at| self.by_pc[at].1)
    }
}

/// The `@` line of a block: where each site is.
fn sites_line(method: &Method<'_>, sites: &[u32]) -> String {
    let mut out = String::from("  @");
    for (index, &pc) in sites.iter().enumerate() {
        out.push_str(if index == 0 { " " } else { ", " });
        out.push_str(&format!("pc {pc:#x}"));
        if let Some(line) = source_line(method, pc) {
            out.push_str(&format!(" line {line}"));
        }
    }
    out.push('\n');
    out
}

/// Whether the block of `context` shows all of `listing`.
fn shows_all(listing: &Listing<'_>, context: RefContext) -> bool {
    context == RefContext::Method && listing.lines.len() <= CONTEXT_MAX_LINES
}

/// The lines of a block below its `@` line.
fn render(listing: &Listing<'_>, sites: &[u32], context: RefContext) -> String {
    let mut out = String::new();
    let lines = &listing.lines;
    let mut hits: Vec<usize> = sites.iter().filter_map(|&pc| listing.line_of(pc)).collect();
    hits.sort_unstable();
    hits.dedup();
    let shown = match context {
        RefContext::None => return out,
        RefContext::Method if shows_all(listing, context) => vec![(0, lines.len())],
        RefContext::Method => {
            out.push_str(&format!("  # function has {} lines; showing {METHOD_FALLBACK_LINES} around each reference\n", lines.len()));
            windows(&hits, METHOD_FALLBACK_LINES, lines.len())
        }
        RefContext::Lines(around) => windows(&hits, around, lines.len()),
    };
    let mut written = 0;
    for (index, &(start, end)) in shown.iter().enumerate() {
        if written + (end - start) > CONTEXT_MAX_LINES {
            let rest: usize = shown[index..].iter().map(|window| window.1 - window.0).sum();
            out.push_str(&format!("  # cut at {CONTEXT_MAX_LINES} lines ({rest} more); read the function with getclass\n"));
            break;
        }
        if index > 0 {
            out.push_str("  --\n");
        }
        for (offset, line) in lines[start..end].iter().enumerate() {
            out.push_str(if hits.binary_search(&(start + offset)).is_ok() { "  > " } else { "    " });
            out.push_str(line);
            out.push('\n');
        }
        written += end - start;
    }
    out
}

/// Fill the `context` of `rows`, which are rows of `abc` in the order a
/// search gave them. A row in a record field has none. A whole function is
/// listed once: the rows that follow it in the same function refer to it.
pub(crate) fn fill(abc: &Abc<'_>, rows: &mut [RefRow], context: RefContext) {
    if context == RefContext::None {
        return;
    }
    // The function of the row before, when all of it was listed there.
    let mut listed: Option<u32> = None;
    for row in rows {
        let (Some(offset), RefSite::Code { .. }) = (row.method, &row.site) else {
            listed = None;
            continue;
        };
        let Ok(method) = abc.method(offset) else {
            row.context = Some("  # context unavailable: the function does not read\n".to_owned());
            listed = None;
            continue;
        };
        let mut block = sites_line(&method, &row.sites);
        if listed == Some(offset) {
            block.push_str("  # the function is listed with the row above\n");
            row.context = Some(block);
            continue;
        }
        let text = method.class_off().and_then(|class| abc.class(class)).map_err(|e| e.to_string());
        let text = text.and_then(|class| disasm::function(abc, &class, &method).map_err(|e| e.to_string()));
        match text {
            Ok(text) => {
                let listing = Listing::of(&text);
                block.push_str(&render(&listing, &row.sites, context));
                listed = shows_all(&listing, context).then_some(offset);
            }
            Err(error) => {
                block.push_str(&format!("  # context unavailable: {error}\n"));
                listed = None;
            }
        }
        row.context = Some(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str =
        ".function f  ; F.f\n; vregs 1\n  0000  lda v0\nL_0002:\n  0002  sta v1\n  0004  lda.str \"a  b\"\n  0007  return\n.end function\n";

    #[test]
    fn instruction_lines_carry_their_offset() {
        assert_eq!(line_pc("  0012  lda v0"), Some(0x12));
        assert_eq!(line_pc("  1a2b3  lda v0"), Some(0x1a2b3));
        for other in ["L_0012:", "  ; line 3", "  .try 0 [0000, 0004) catchall -> L_0008", ".function f", "  12  x", "    0012  x"] {
            assert_eq!(line_pc(other), None, "{other}");
        }
        let listing = Listing::of(TEXT);
        assert_eq!((listing.line_of(0), listing.line_of(2), listing.line_of(4), listing.line_of(3)), (Some(2), Some(4), Some(5), None));
    }

    #[test]
    fn windows_merge_where_they_touch() {
        assert_eq!(windows(&[2, 5], 1, 8), [(1, 7)]);
        assert_eq!(windows(&[1, 6], 1, 8), [(0, 3), (5, 8)]);
        assert_eq!(windows(&[0], 0, 8), [(0, 1)]);
        assert!(windows(&[], 3, 8).is_empty());
    }

    #[test]
    fn blocks_mark_the_sites() {
        let listing = Listing::of(TEXT);
        assert_eq!(render(&listing, &[4], RefContext::Lines(1)), "      0002  sta v1\n  >   0004  lda.str \"a  b\"\n      0007  return\n");
        assert_eq!(render(&listing, &[0, 7], RefContext::Lines(0)), "  >   0000  lda v0\n  --\n  >   0007  return\n");
        let whole = render(&listing, &[2], RefContext::Method);
        assert_eq!(whole.lines().count(), 8);
        assert!(whole.starts_with("    .function f  ; F.f\n") && whole.contains("\n    L_0002:\n  >   0002  sta v1\n"), "{whole}");
        assert_eq!(render(&listing, &[2], RefContext::None), "");

        // A long function falls back to windows, and a block is cut at the limit.
        let long: String = (0..400).map(|pc| format!("  {pc:04x}  nop\n")).collect();
        let listing = Listing::of(&long);
        let block = render(&listing, &[0x10, 0x100], RefContext::Method);
        assert!(block.starts_with("  # function has 400 lines; showing 10 around each reference\n"), "{block}");
        assert_eq!(block.lines().filter(|line| line.starts_with("  > ")).count(), 2);
        let cut = render(&listing, &[0x10, 0x100], RefContext::Lines(60));
        assert!(cut.ends_with("  # cut at 150 lines (121 more); read the function with getclass\n"), "{cut}");
    }
}
