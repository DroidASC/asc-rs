//! Reference-search state: one entry per search kept as history, each tagged
//! with a generation number so late events from a cancelled search never land
//! in a newer one. Pure logic, no egui.

use asc_engine::RefResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Oldest searches are evicted past this many entries.
pub const HISTORY_LIMIT: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SearchKind {
    String,
    Type,
    Method,
    Field,
}

impl SearchKind {
    pub const ALL: [SearchKind; 4] = [SearchKind::String, SearchKind::Type, SearchKind::Method, SearchKind::Field];

    pub fn label(self) -> &'static str {
        match self {
            SearchKind::String => "string refs",
            SearchKind::Type => "type refs",
            SearchKind::Method => "method refs",
            SearchKind::Field => "field refs",
        }
    }

    pub fn is_member(self) -> bool {
        matches!(self, SearchKind::Method | SearchKind::Field)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SearchKind::String => "string",
            SearchKind::Type => "type",
            SearchKind::Method => "method",
            SearchKind::Field => "field",
        }
    }

    pub fn parse(s: &str) -> Option<SearchKind> {
        SearchKind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

pub struct SearchState {
    pub gen: u64,
    pub title: String,
    pub results: Vec<RefResult>,
    /// Display line per result, formatted once.
    lines: Vec<String>,
    /// Lower-cased copy of `lines`, so the filter never re-allocates per row.
    lower: Vec<String>,
    pub filter: String,
    /// The filter text `filtered` was computed for; `None` forces a rebuild.
    applied_filter: Option<String>,
    filtered: Vec<usize>,
    pub done: usize,
    pub total: usize,
    pub hits: usize,
    pub finished: bool,
    /// The user cancelled this search; `results` are partial.
    pub cancelled: bool,
    /// The search itself failed (no results at all).
    pub error: Option<String>,
    /// Per-DEX failures; results of the other DEX entries are still valid.
    pub errors: Vec<String>,
    pub cancel: Arc<AtomicBool>,
    /// Maximum rows kept; anything past it is counted in `dropped`.
    pub cap: usize,
    pub dropped: usize,
}

impl SearchState {
    pub fn new(gen: u64, title: String, cap: usize) -> SearchState {
        SearchState {
            gen,
            title,
            results: Vec::new(),
            lines: Vec::new(),
            lower: Vec::new(),
            filter: String::new(),
            applied_filter: None,
            filtered: Vec::new(),
            done: 0,
            total: 0,
            hits: 0,
            finished: false,
            cancelled: false,
            error: None,
            errors: Vec::new(),
            cancel: Arc::new(AtomicBool::new(false)),
            cap,
            dropped: 0,
        }
    }

    pub fn push(&mut self, mut rows: Vec<RefResult>) {
        let room = self.cap.saturating_sub(self.results.len());
        if rows.len() > room {
            self.dropped += rows.len() - room;
            rows.truncate(room);
        }
        let start = self.lines.len();
        for r in &rows {
            let line = format!("{}  {}  ({})", r.dex_name, r.method, r.matched.join("; "));
            self.lower.push(line.to_lowercase());
            self.lines.push(line);
        }
        self.results.append(&mut rows);
        // Extend the visible set incrementally instead of re-filtering
        // everything on the next frame.
        if let Some(applied) = &self.applied_filter {
            let kw = applied.to_lowercase();
            self.filtered.extend((start..self.lines.len()).filter(|&i| kw.is_empty() || self.lower[i].contains(&kw)));
        }
    }

    /// Recompute the visible rows if the filter changed.
    pub fn refresh_filter(&mut self) {
        if self.applied_filter.as_deref() == Some(self.filter.as_str()) {
            return;
        }
        let kw = self.filter.to_lowercase();
        self.filtered = if kw.is_empty() {
            (0..self.lines.len()).collect()
        } else {
            self.lower.iter().enumerate().filter(|(_, l)| l.contains(&kw)).map(|(i, _)| i).collect()
        };
        self.applied_filter = Some(self.filter.clone());
    }

    /// Indexes into `results` that pass the filter (call `refresh_filter` first).
    pub fn visible(&self) -> &[usize] {
        &self.filtered
    }

    pub fn line(&self, i: usize) -> &str {
        &self.lines[i]
    }

    pub fn running(&self) -> bool {
        !self.finished
    }

    /// Ask the worker to stop; whatever arrived so far stays as partial results.
    pub fn cancel(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if !self.finished {
            self.cancelled = true;
        }
    }

    /// One-line summary for the results header / status bar.
    pub fn summary(&self) -> String {
        let n = self.hits;
        let mut s = if self.cancelled { format!("cancelled ({n} partial results)") } else { format!("{n} results") };
        if self.dropped > 0 {
            s.push_str(&format!(", {} not kept (row limit)", self.dropped));
        }
        if !self.errors.is_empty() {
            s.push_str(&format!(", {} DEX failed", self.errors.len()));
        }
        s
    }

    /// All kept results in the CLI line format.
    pub fn export(&self) -> String {
        self.results.iter().map(RefResult::line).collect::<Vec<_>>().join("\n")
    }
}

/// The search history shown in the bottom panel.
pub struct SearchPanel {
    pub states: Vec<SearchState>,
    pub active: usize,
    pub open: bool,
    next_gen: u64,
}

impl Default for SearchPanel {
    fn default() -> Self {
        SearchPanel { states: Vec::new(), active: 0, open: false, next_gen: 1 }
    }
}

impl SearchPanel {
    /// Register a new search and make it active; returns its generation and
    /// cancel flag.
    pub fn begin(&mut self, title: String, cap: usize) -> (u64, Arc<AtomicBool>) {
        let gen = self.next_gen;
        self.next_gen += 1;
        self.evict();
        let state = SearchState::new(gen, title, cap);
        let cancel = state.cancel.clone();
        self.states.push(state);
        self.active = self.states.len() - 1;
        self.open = true;
        (gen, cancel)
    }

    fn evict(&mut self) {
        while self.states.len() >= HISTORY_LIMIT {
            let victim = self.states.iter().position(|s| s.finished).unwrap_or(0);
            self.close(victim);
        }
    }

    pub fn get(&mut self, gen: u64) -> Option<&mut SearchState> {
        self.states.iter_mut().find(|s| s.gen == gen)
    }

    pub fn close(&mut self, i: usize) {
        if i >= self.states.len() {
            return;
        }
        self.states[i].cancel();
        self.states.remove(i);
        self.active = crate::tabs::active_after_close(self.active, i, self.states.len());
    }

    pub fn any_running(&self) -> bool {
        self.states.iter().any(SearchState::running)
    }

    /// Index of a still-running search with this title.
    pub fn running_titled(&self, title: &str) -> Option<usize> {
        self.states.iter().position(|s| s.running() && s.title == title)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(m: &str) -> RefResult {
        RefResult { dex_name: "classes.dex".into(), method_idx: 0, method: m.into(), matched: vec!["x".into()] }
    }

    #[test]
    fn stale_generation_is_not_routed() {
        let mut panel = SearchPanel::default();
        let (old, old_cancel) = panel.begin("old".into(), 10);
        let (new, _) = panel.begin("new".into(), 10);
        old_cancel.store(true, Ordering::Relaxed);
        panel.close(0);
        assert!(panel.get(old).is_none());
        panel.get(new).unwrap().push(vec![row("Lx;->a")]);
        assert_eq!(panel.states.len(), 1);
        assert_eq!(panel.states[0].results.len(), 1);
        assert_eq!(panel.active, 0);
    }

    #[test]
    fn cap_counts_dropped_rows() {
        let mut s = SearchState::new(1, "t".into(), 3);
        s.push(vec![row("a"), row("b")]);
        s.push(vec![row("c"), row("d"), row("e")]);
        assert_eq!(s.results.len(), 3);
        assert_eq!(s.dropped, 2);
    }

    #[test]
    fn filter_is_cached_until_it_changes() {
        let mut s = SearchState::new(1, "t".into(), 10);
        s.push(vec![row("Lx;->alpha"), row("Ly;->beta")]);
        s.refresh_filter();
        assert_eq!(s.visible(), &[0, 1]);
        s.filter = "BETA".into();
        s.refresh_filter();
        assert_eq!(s.visible(), &[1]);
        s.push(vec![row("Lz;->betamax")]);
        assert_eq!(s.visible(), &[1, 2], "push extends the visible set without a refresh");
        s.refresh_filter();
        assert_eq!(s.visible(), &[1, 2]);
        s.filter.clear();
        s.refresh_filter();
        assert_eq!(s.visible(), &[0, 1, 2]);
        s.push(vec![row("Lw;->gamma")]);
        assert_eq!(s.visible(), &[0, 1, 2, 3]);
    }

    #[test]
    fn cancel_marks_partial_results() {
        let mut s = SearchState::new(1, "t".into(), 10);
        s.hits = 3;
        s.cancel();
        assert!(s.cancelled);
        assert!(s.cancel.load(Ordering::Relaxed));
        assert_eq!(s.summary(), "cancelled (3 partial results)");
        let mut s = SearchState::new(2, "t".into(), 10);
        s.hits = 7;
        s.finished = true;
        s.errors.push("classes3.dex: bad".into());
        s.cancel();
        assert!(!s.cancelled, "cancelling a finished search changes nothing");
        assert_eq!(s.summary(), "7 results, 1 DEX failed");
    }

    #[test]
    fn history_evicts_finished_first() {
        let mut panel = SearchPanel::default();
        for i in 0..HISTORY_LIMIT {
            panel.begin(format!("s{i}"), 10);
        }
        panel.states[3].finished = true;
        panel.begin("newest".into(), 10);
        assert_eq!(panel.states.len(), HISTORY_LIMIT);
        assert!(panel.states.iter().all(|s| s.title != "s3"));
        assert_eq!(panel.states[panel.active].title, "newest");
    }

    #[test]
    fn kind_round_trips() {
        for k in SearchKind::ALL {
            assert_eq!(SearchKind::parse(k.as_str()), Some(k));
        }
    }
}
