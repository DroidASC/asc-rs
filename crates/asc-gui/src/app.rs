//! The egui application: layout, event routing and user actions.
//!
//! Widgets never mutate application state directly. They push an [`Action`]
//! while drawing and the actions are applied once the frame is laid out, so
//! any part of the UI can trigger any operation without borrow gymnastics.

use crate::members::{char_to_byte, member_at, member_spans_in_line, MemberKind, MemberSpan};
use crate::prefs::{row_cap_label, Prefs, ROW_CAPS};
use crate::search::{SearchKind, SearchPanel};
use crate::store::{ClassEntry, ClassIndex, Event, LoadedIndex, Package, Store};
use crate::tabs::{active_after_close, const_string_in_line, descriptors_in_line, regex_escape, short_name, Jump, Tab, TabContent};
use asc_engine::{names, Engine};
use asc_findrefs::{ClassQuery, MemberQuery, Query};
use egui::text::{CCursor, LayoutJob, TextFormat};
use egui::{Color32, Key, Modifiers, RichText, Stroke, TextStyle};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

const MAX_FILTER_RESULTS: usize = 500;
const MAX_SUGGESTIONS: usize = 12;
const LOG_LIMIT: usize = 50;
const MANIFEST_TAB: &str = "manifest";

const HELP: &str = "Ctrl+L   focus the search box\n\
Ctrl+F   find in the current tab\n\
F3 / Shift+F3   next / previous find match\n\
Ctrl+W   close the current tab\n\
Esc      close the find bar\n\
X        find references to the method / field under the cursor\n\
Ctrl+click   go to the declaration of a method / field\n\
\n\
Click a source line to place the cursor; hold Ctrl to show member links.\n\
Right-click a class, a source line or a result row for actions.\n\
Double-click a result row to open the method.\n\
Type two or more characters in the class field for suggestions.";

/// Deferred UI operations (see module docs).
enum Action {
    OpenClass {
        descriptor: String,
        jump: Option<Jump>,
    },
    /// Open the declaring class of a referenced member at its declaration.
    GotoMember(MemberSpan),
    OpenManifest,
    RetryTab(String),
    RetryLoad,
    /// `exact`: match the member name as a whole (member kinds only).
    Search {
        kind: SearchKind,
        value: String,
        class: String,
        fuzzy: bool,
        exact: bool,
    },
    Copy(String),
    CloseTab(usize),
    CloseSearch(usize),
    CancelSearch(usize),
}

impl Action {
    /// A type-reference search for one exact descriptor.
    fn find_type(descriptor: &str) -> Action {
        Action::Search { kind: SearchKind::Type, value: regex_escape(descriptor), class: String::new(), fuzzy: false, exact: false }
    }

    /// A reference search for exactly this member of exactly this class.
    fn find_member(m: &MemberSpan) -> Action {
        let kind = match m.kind {
            MemberKind::Method => SearchKind::Method,
            MemberKind::Field => SearchKind::Field,
        };
        Action::Search { kind, value: m.name.clone(), class: m.class.clone(), fuzzy: false, exact: true }
    }

    fn open(descriptor: &str, jump: Option<Jump>) -> Action {
        Action::OpenClass { descriptor: descriptor.to_string(), jump }
    }
}

struct LoadInfo {
    classes: usize,
    dex: usize,
    ms: u128,
    /// DEX entries that could not be indexed (`entry: error`).
    failed: Vec<String>,
}

#[derive(Clone, Copy)]
enum SuggestTarget {
    Value,
    Class,
}

pub struct AscApp {
    store: Arc<Store>,
    rx: Receiver<Event>,
    debug: bool,
    prefs: Prefs,
    /// Recent status messages, newest last.
    log: VecDeque<String>,
    index: Option<ClassIndex>,
    load_progress: (usize, usize),
    load_error: Option<String>,
    load_info: Option<LoadInfo>,
    class_filter: String,
    /// `(filter text, matching indexes)` so the tree filter runs once per edit.
    class_filter_cache: (String, Vec<usize>),
    /// `(query text, descriptors)` so the suggestion popup filters once per edit.
    suggest_cache: (String, Vec<String>),
    tabs: Vec<Tab>,
    active: usize,
    /// Last id handed to [`Store::open_class`]; see [`Tab::req`].
    next_class_req: u64,
    search_value: String,
    search_class: String,
    /// The "exact name" box: match member names as a whole in searches
    /// submitted from the top bar ("find references" on a member is always
    /// exact and leaves it alone).
    exact_name: bool,
    suggest_open: bool,
    search: SearchPanel,
    show_find: bool,
    focus_find: bool,
    focus_search: bool,
    actions: Vec<Action>,
}

impl AscApp {
    pub fn new(cc: &eframe::CreationContext<'_>, apk: PathBuf, threads: usize, debug: bool, cache: asc_engine::CacheConfig) -> AscApp {
        Self::with_context(cc.egui_ctx.clone(), Prefs::load(cc.storage), apk, threads, debug, cache)
    }

    fn with_context(ctx: egui::Context, prefs: Prefs, apk: PathBuf, threads: usize, debug: bool, cache: asc_engine::CacheConfig) -> AscApp {
        let mut engine = Engine::new(&apk).with_threads(threads).with_debug(debug).with_logger(|m| eprintln!("{m}"));
        // Inflated DEX files and their locator tables stay resident within
        // the caller's budget (by default it follows the free memory, so
        // several open browsers do not each claim 2 GiB).
        engine = engine.with_cache(cache);
        let engine = Arc::new(engine);
        let (tx, rx) = channel();
        let store = Arc::new(Store { engine, tx, ctx });
        store.load_index();
        let mut app = AscApp {
            store,
            rx,
            debug,
            prefs,
            log: VecDeque::new(),
            index: None,
            load_progress: (0, 0),
            load_error: None,
            load_info: None,
            class_filter: String::new(),
            class_filter_cache: (String::new(), Vec::new()),
            suggest_cache: (String::new(), Vec::new()),
            tabs: Vec::new(),
            active: 0,
            next_class_req: 0,
            search_value: String::new(),
            search_class: String::new(),
            exact_name: false,
            suggest_open: false,
            search: SearchPanel::default(),
            show_find: false,
            focus_find: false,
            focus_search: false,
            actions: Vec::new(),
        };
        app.note(format!("Loading {}...", apk.display()));
        app
    }

    fn note(&mut self, msg: impl Into<String>) {
        self.log.push_back(msg.into());
        while self.log.len() > LOG_LIMIT {
            self.log.pop_front();
        }
    }

    // ---- events -----------------------------------------------------------

    fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::LoadProgress { done, total } => self.load_progress = (done, total),
                Event::Loaded { result: Ok(LoadedIndex { index, failed }), elapsed_ms } => {
                    let mut msg = format!("{} classes in {} DEX, indexed in {elapsed_ms} ms", index.len(), index.dex_count);
                    if !failed.is_empty() {
                        msg.push_str(&format!("; {} DEX could not be indexed: {}", failed.len(), failed.join("; ")));
                    }
                    self.load_info = Some(LoadInfo { classes: index.len(), dex: index.dex_count, ms: elapsed_ms, failed });
                    self.load_error = None;
                    self.class_filter_cache = (String::new(), Vec::new());
                    self.suggest_cache = (String::new(), Vec::new());
                    self.note(msg);
                    self.index = Some(index);
                }
                Event::Loaded { result: Err(e), .. } => {
                    self.note(format!("Load failed: {e}"));
                    self.load_error = Some(e);
                }
                Event::ClassOpened { descriptor, req, result } => {
                    // A reply for a tab that was closed (and maybe reopened,
                    // with a newer request id) in the meantime is stale.
                    let Some(tab) = self.tabs.iter_mut().find(|t| t.accepts(&descriptor, req)) else { continue };
                    let msg = match result {
                        Ok(src) => {
                            tab.subtitle = format!("{descriptor}  [{}]", src.dex_name);
                            let unresolved = tab.set_text(&src.source);
                            let msg = format!("Opened {descriptor} from {} in {} ms", src.dex_name, src.scan_ms);
                            if let Some(j) = unresolved {
                                self.note(unresolved_note(&descriptor, &j));
                            }
                            if let Some(w) = src.warning {
                                self.note(format!("{descriptor}: {w}"));
                            }
                            msg
                        }
                        Err(e) => {
                            tab.set_error(e.clone());
                            format!("{descriptor}: {e}")
                        }
                    };
                    self.note(msg);
                }
                Event::Manifest(result) => {
                    let msg = match result {
                        Ok(xml) => {
                            if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == MANIFEST_TAB) {
                                let _ = tab.set_text(&xml);
                            }
                            "Manifest decoded".to_string()
                        }
                        Err(e) => {
                            if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == MANIFEST_TAB) {
                                tab.set_error(e.clone());
                            }
                            format!("Manifest: {e}")
                        }
                    };
                    self.note(msg);
                }
                Event::SearchProgress { gen, done, total, hits } => {
                    if let Some(s) = self.search.get(gen) {
                        s.done = done;
                        s.total = total;
                        s.hits = hits;
                    }
                }
                Event::SearchResults { gen, rows } => {
                    if let Some(s) = self.search.get(gen) {
                        s.push(rows);
                    }
                }
                Event::SearchError { gen, message } => {
                    let Some(s) = self.search.get(gen) else { continue };
                    s.errors.push(message.clone());
                    let title = s.title.clone();
                    self.note(format!("{title}: {message}"));
                }
                Event::SearchDone { gen, result } => {
                    let Some(s) = self.search.get(gen) else { continue };
                    s.finished = true;
                    let msg = match result {
                        Ok(_) => format!("{}: {}", s.title, s.summary()),
                        Err(e) => {
                            s.error = Some(e.clone());
                            format!("{}: {e}", s.title)
                        }
                    };
                    self.note(msg);
                }
            }
        }
    }

    // ---- actions ----------------------------------------------------------

    fn apply_actions(&mut self) {
        for action in std::mem::take(&mut self.actions) {
            match action {
                Action::OpenClass { descriptor, jump } => self.open_class(&descriptor, jump),
                Action::GotoMember(m) => self.goto_member(m),
                Action::OpenManifest => self.open_manifest(),
                Action::RetryTab(id) => {
                    if id == MANIFEST_TAB {
                        self.open_manifest();
                    } else if let Some(i) = self.tabs.iter().position(|t| t.id == id) {
                        self.request_class(i);
                    }
                }
                Action::RetryLoad => {
                    self.load_error = None;
                    self.load_progress = (0, 0);
                    self.note("Reloading class index...");
                    self.store.load_index();
                }
                Action::Search { kind, value, class, fuzzy, exact } => {
                    self.prefs.search_kind = kind;
                    self.prefs.fuzzy_class = fuzzy;
                    self.search_value = value;
                    self.search_class = class;
                    self.suggest_open = false;
                    // `exact` applies to this search only (as in the Python
                    // GUI): the "exact name" box keeps what the user set, so
                    // a later hand-typed regex is not silently taken literally.
                    self.start_search(exact && kind.is_member());
                }
                Action::Copy(text) => self.store.ctx.copy_text(text),
                Action::CloseTab(i) => self.close_tab(i),
                Action::CloseSearch(i) => self.search.close(i),
                Action::CancelSearch(i) => {
                    if let Some(s) = self.search.states.get_mut(i) {
                        s.cancel();
                    }
                }
            }
        }
    }

    fn close_tab(&mut self, i: usize) {
        if i < self.tabs.len() {
            self.tabs.remove(i);
            self.active = active_after_close(self.active, i, self.tabs.len());
        }
    }

    /// Start (or restart) the extraction for the tab at `i` with a fresh
    /// request id, so a reply to any earlier request for it is ignored.
    fn request_class(&mut self, i: usize) {
        self.next_class_req += 1;
        let tab = &mut self.tabs[i];
        tab.req = self.next_class_req;
        tab.set_loading();
        self.store.open_class(tab.id.clone(), tab.req);
    }

    /// Open (or focus) the tab for `descriptor`, optionally jumping to a
    /// declaration.
    fn open_class(&mut self, descriptor: &str, jump: Option<Jump>) {
        let descriptor = match names::format_class_name(descriptor) {
            Ok(d) => d,
            Err(e) => {
                self.note(e.to_string());
                return;
            }
        };
        if let Some(i) = self.tabs.iter().position(|t| t.id == descriptor) {
            self.active = i;
            let tab = &mut self.tabs[i];
            match tab.content {
                TabContent::Text(_) => {
                    if let Some(j) = jump {
                        if !tab.jump_to(&j) {
                            self.note(unresolved_note(&descriptor, &j));
                        }
                    }
                }
                // Already being extracted: just remember where to jump. A
                // plain re-open (tree, search result) keeps an earlier
                // Ctrl+click target instead of dropping it.
                TabContent::Loading => {
                    if jump.is_some() {
                        tab.pending_jump = jump;
                    }
                }
                TabContent::Error(_) => {
                    if jump.is_some() {
                        tab.pending_jump = jump;
                    }
                    self.request_class(i);
                }
            }
            return;
        }
        let mut tab = Tab::loading(descriptor.clone(), short_name(&descriptor), descriptor.clone());
        tab.pending_jump = jump;
        self.tabs.push(tab);
        self.active = self.tabs.len() - 1;
        self.note(format!("Extracting {descriptor}..."));
        self.request_class(self.active);
    }

    /// Ctrl+click on a member reference: open its class at the declaration.
    fn goto_member(&mut self, m: MemberSpan) {
        if self.index.as_ref().is_some_and(|ix| !ix.contains(&m.class)) {
            self.note(format!("Declaration class is not present in this APK: {}", names::dalvik_to_dot(&m.class)));
            return;
        }
        let jump = Jump::Member { kind: m.kind, name: m.name, descriptor: m.descriptor };
        self.open_class(&m.class, Some(jump));
    }

    /// The `X` shortcut: search references to the member under the caret.
    fn find_member_at_caret(&mut self) {
        let Some(tab) = self.tabs.get(self.active) else { return };
        if tab.id == MANIFEST_TAB || !matches!(tab.content, TabContent::Text(_)) {
            return;
        }
        let member = tab.caret.and_then(|(line, col)| tab.lines().get(line).and_then(|l| member_at(l, &tab.id, col)));
        match member {
            Some(m) => self.actions.push(Action::find_member(&m)),
            None => self.note("Place the cursor on a method or field name to find its references"),
        }
    }

    fn open_manifest(&mut self) {
        if let Some(i) = self.tabs.iter().position(|t| t.id == MANIFEST_TAB) {
            self.active = i;
            if !self.tabs[i].is_error() {
                return;
            }
            self.tabs[i].set_loading();
        } else {
            self.tabs.push(Tab::loading(MANIFEST_TAB.into(), "AndroidManifest.xml".into(), "AndroidManifest.xml".into()));
            self.active = self.tabs.len() - 1;
        }
        self.note("Decoding manifest...");
        self.store.open_manifest();
    }

    /// Run the search described by the top bar; `exact` matches member names
    /// as a whole.
    fn start_search(&mut self, exact: bool) {
        let kind = self.prefs.search_kind;
        let value = self.search_value.trim().to_string();
        let class = self.search_class.trim().to_string();
        let query = match kind {
            SearchKind::String => Query::String(value.clone()),
            SearchKind::Type => Query::Type(value.clone()),
            SearchKind::Method | SearchKind::Field => {
                let q = match names::member_query(kind.as_str(), Some(class.as_str()), self.prefs.fuzzy_class, Some(value.as_str()), exact)
                {
                    Ok(q) => q,
                    Err(e) => {
                        self.note(e.to_string());
                        return;
                    }
                };
                if kind == SearchKind::Method {
                    Query::Method(q)
                } else {
                    Query::Field(q)
                }
            }
        };
        if matches!(query, Query::String(ref v) | Query::Type(ref v) if v.is_empty()) {
            self.note("Search value cannot be empty");
            return;
        }
        let title = match &query {
            Query::String(v) => format!("string: {v}"),
            Query::Type(v) => format!("type: {v}"),
            // Not issued by the GUI; named for completeness.
            Query::StringLiteral(v) => format!("string (literal): {v}"),
            Query::Extends(v) => format!("extends: {v}"),
            Query::Implements(v) => format!("impl: {v}"),
            Query::All { all, none } => format!("all of {}, none of {}", all.len(), none.len()),
            Query::Method(MemberQuery { class, name, exact_name }) | Query::Field(MemberQuery { class, name, exact_name }) => format!(
                "{}: {}{}{}",
                kind.as_str(),
                class.as_ref().map(|c: &ClassQuery| format!("{}{}->", c.pattern, if c.precise { "" } else { "*" })).unwrap_or_default(),
                name.clone().unwrap_or_default(),
                if *exact_name && name.is_some() { " (exact)" } else { "" }
            ),
        };
        // The same query still running (e.g. `X` pressed twice): show it
        // instead of starting a duplicate that would push history out.
        if let Some(i) = self.search.running_titled(&title) {
            self.search.active = i;
            self.search.open = true;
            self.note(format!("Already searching {title}"));
            return;
        }
        let (gen, cancel) = self.search.begin(title.clone(), self.prefs.cap());
        self.note(format!("Searching {title}..."));
        self.store.search(query, gen, cancel);
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let (find, close, focus, next, prev, esc) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::COMMAND, Key::F),
                i.consume_key(Modifiers::COMMAND, Key::W),
                i.consume_key(Modifiers::COMMAND, Key::L),
                i.consume_key(Modifiers::NONE, Key::F3),
                i.consume_key(Modifiers::SHIFT, Key::F3),
                i.key_pressed(Key::Escape),
            )
        });
        // A bare letter is a shortcut only while no text field has focus
        // (source lines are not focusable, see `source_view`).
        // Auto-repeat events of a held key are ignored: each would start
        // another whole-APK search.
        let xref = !ctx.wants_keyboard_input()
            && ctx.input_mut(|i| {
                let fresh = i.events.iter().any(|e| {
                    matches!(e, egui::Event::Key { key: Key::X, pressed: true, repeat: false, modifiers, .. }
                        if modifiers.matches_logically(Modifiers::NONE))
                });
                i.consume_key(Modifiers::NONE, Key::X) && fresh
            });
        if xref {
            self.find_member_at_caret();
        }
        if find {
            self.show_find = true;
            self.focus_find = true;
        }
        if close && !self.tabs.is_empty() {
            self.close_tab(self.active.min(self.tabs.len() - 1));
        }
        if focus {
            self.focus_search = true;
        }
        if esc && self.show_find {
            self.show_find = false;
        }
        if next || prev {
            if let Some(tab) = self.tabs.get_mut(self.active) {
                tab.step_find(prev);
            }
        }
    }

    // ---- UI: top bar --------------------------------------------------------

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("search_kind").selected_text(self.prefs.search_kind.label()).show_ui(ui, |ui| {
                for k in SearchKind::ALL {
                    ui.selectable_value(&mut self.prefs.search_kind, k, k.label());
                }
            });
            let kind = self.prefs.search_kind;
            let hint = match kind {
                SearchKind::String => "string pattern (regex)",
                SearchKind::Type => "type descriptor or pattern (regex)",
                _ if self.exact_name => "member name (exact)",
                _ => "member name (regex)",
            };
            let value = ui.add(egui::TextEdit::singleline(&mut self.search_value).hint_text(hint).desired_width(260.0));
            if self.focus_search {
                value.request_focus();
                self.focus_search = false;
            }
            let enter = ui.input(|i| i.key_pressed(Key::Enter));
            let mut submit = value.lost_focus() && enter;
            if kind == SearchKind::Type {
                self.suggestions(ui, &value, SuggestTarget::Value);
            }
            if kind.is_member() {
                let class =
                    ui.add(egui::TextEdit::singleline(&mut self.search_class).hint_text("class (Lcom/x/Y; or fuzzy)").desired_width(260.0));
                submit |= class.lost_focus() && enter;
                self.suggestions(ui, &class, SuggestTarget::Class);
                ui.checkbox(&mut self.prefs.fuzzy_class, "fuzzy class")
                    .on_hover_text("Match the class field as a substring / regex instead of an exact descriptor");
                ui.checkbox(&mut self.exact_name, "exact name")
                    .on_hover_text("Match the member name as a whole instead of as a regex (substring with an exact class)");
            }
            if ui.button("Search").clicked() {
                submit = true;
            }
            if submit {
                self.actions.push(Action::Search {
                    kind,
                    value: self.search_value.clone(),
                    class: self.search_class.clone(),
                    fuzzy: self.prefs.fuzzy_class,
                    exact: self.exact_name,
                });
            }
            ui.separator();
            if ui.button("Manifest").clicked() {
                self.actions.push(Action::OpenManifest);
            }
            ui.label(RichText::new("rows").weak());
            egui::ComboBox::from_id_salt("row_cap").selected_text(row_cap_label(self.prefs.row_cap)).width(90.0).show_ui(ui, |ui| {
                for cap in ROW_CAPS {
                    ui.selectable_value(&mut self.prefs.row_cap, cap, row_cap_label(cap));
                }
            });
            if self.prefs.row_cap == 0 {
                ui.label(RichText::new("⚠").color(ui.visuals().warn_fg_color))
                    .on_hover_text("No row limit: a broad search may keep a very large result set in memory");
            }
            ui.separator();
            egui::global_theme_preference_switch(ui);
            if !self.search.states.is_empty() && !self.search.open && ui.button("Results").clicked() {
                self.search.open = true;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new("?").strong()).on_hover_text(HELP);
            });
        });
    }

    /// Class-name suggestions under a search field, fed by the class index.
    fn suggestions(&mut self, ui: &mut egui::Ui, resp: &egui::Response, target: SuggestTarget) {
        let text = match target {
            SuggestTarget::Value => self.search_value.trim(),
            SuggestTarget::Class => self.search_class.trim(),
        };
        if resp.changed() {
            self.suggest_open = text.len() >= 2;
        }
        if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter) || i.key_pressed(Key::Escape)) {
            self.suggest_open = false;
        }
        if !self.suggest_open {
            return;
        }
        let Some(index) = &self.index else { return };
        if self.suggest_cache.0 != text {
            let matches = index.filter(text, MAX_SUGGESTIONS).into_iter().map(|i| index.descriptor(i).to_string()).collect();
            self.suggest_cache = (text.to_string(), matches);
        }
        let matches = &self.suggest_cache.1;
        if matches.is_empty() {
            return;
        }
        let mut open = self.suggest_open;
        let mut picked: Option<String> = None;
        egui::Popup::from_response(resp)
            .open_bool(&mut open)
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .width(resp.rect.width().max(360.0))
            .show(|ui| {
                for d in matches {
                    if ui.selectable_label(false, names::dalvik_to_dot(d)).on_hover_text(d).clicked() {
                        picked = Some(d.clone());
                    }
                }
            });
        self.suggest_open = open;
        if let Some(d) = picked {
            match target {
                SuggestTarget::Value => self.search_value = regex_escape(&d),
                SuggestTarget::Class => self.search_class = d,
            }
            self.suggest_open = false;
        }
    }

    // ---- UI: class tree -----------------------------------------------------

    fn class_tree(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut self.class_filter).hint_text("class or package").desired_width(f32::INFINITY));
        });
        ui.separator();
        if let Some(e) = &self.load_error {
            ui.colored_label(ui.visuals().error_fg_color, "Failed to load the class index");
            ui.label(RichText::new(e).small());
            if ui.button("Retry").clicked() {
                self.actions.push(Action::RetryLoad);
            }
            return;
        }
        let Some(index) = &self.index else {
            let (done, total) = self.load_progress;
            if total > 0 {
                ui.add(egui::ProgressBar::new(done as f32 / total as f32).text(format!("{done}/{total} DEX")));
            } else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Opening APK...");
                });
            }
            return;
        };
        if let Some(info) = self.load_info.as_ref().filter(|i| !i.failed.is_empty()) {
            ui.colored_label(ui.visuals().warn_fg_color, format!("{} DEX could not be indexed", info.failed.len())).on_hover_ui(|ui| {
                for f in &info.failed {
                    ui.label(RichText::new(f).small());
                }
            });
        }
        let filter = self.class_filter.trim();
        let selected = self.tabs.get(self.active).map(|t| t.id.as_str());
        let actions = &mut self.actions;
        if !filter.is_empty() && self.class_filter_cache.0 != filter {
            self.class_filter_cache = (filter.to_string(), index.filter(filter, MAX_FILTER_RESULTS));
        }
        let cache = &self.class_filter_cache.1;
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            if filter.is_empty() {
                render_package(ui, index.root(), "", actions, selected);
            } else {
                if cache.len() >= MAX_FILTER_RESULTS {
                    ui.label(RichText::new(format!("showing the first {MAX_FILTER_RESULTS} matches")).weak());
                } else {
                    ui.label(RichText::new(format!("{} matches", cache.len())).weak());
                }
                for &i in cache {
                    render_class(ui, index.get(i), actions, selected, true);
                }
            }
        });
    }

    // ---- UI: editor ---------------------------------------------------------

    fn editor(&mut self, ui: &mut egui::Ui) {
        if self.tabs.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Select a class on the left, search for references above, or open the manifest.").weak());
            });
            return;
        }
        let strip = ui
            .horizontal_wrapped(|ui| {
                let items = self.tabs.iter().map(|t| (t.title.as_str(), t.is_loading(), t.subtitle.as_str()));
                tab_strip(ui, items, self.active, "close (Ctrl+W)")
            })
            .inner;
        if let Some(i) = strip.clicked {
            self.active = i;
        }
        if let Some(i) = strip.closed {
            self.actions.push(Action::CloseTab(i));
        }
        let active = self.active.min(self.tabs.len() - 1);
        self.active = active;
        let tab = &mut self.tabs[active];
        let index = self.index.as_ref();
        let actions = &mut self.actions;
        ui.horizontal(|ui| {
            ui.label(RichText::new(&tab.subtitle).weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let TabContent::Text(lines) = &tab.content {
                    if ui.button("Copy all").clicked() {
                        actions.push(Action::Copy(lines.join("\n")));
                    }
                    if ui.selectable_label(self.show_find, "Find").on_hover_text("Ctrl+F").clicked() {
                        self.show_find = !self.show_find;
                        self.focus_find = self.show_find;
                    }
                }
            });
        });
        if self.show_find && matches!(tab.content, TabContent::Text(_)) {
            ui.horizontal(|ui| {
                ui.label("Find");
                let r = ui.add(egui::TextEdit::singleline(&mut tab.find).desired_width(240.0));
                if self.focus_find {
                    r.request_focus();
                    self.focus_find = false;
                }
                if r.changed() {
                    tab.refresh_find();
                }
                if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    tab.step_find(ui.input(|i| i.modifiers.shift));
                    r.request_focus();
                }
                if ui.button("Prev").on_hover_text("Shift+F3").clicked() {
                    tab.step_find(true);
                }
                if ui.button("Next").on_hover_text("F3").clicked() {
                    tab.step_find(false);
                }
                if !tab.find.is_empty() {
                    let shown = if tab.find_matches.is_empty() { 0 } else { tab.find_cursor + 1 };
                    ui.label(format!("{shown}/{}", tab.find_matches.len()));
                }
                if ui.button("Close").on_hover_text("Esc").clicked() {
                    self.show_find = false;
                }
            });
        }
        ui.separator();
        match &tab.content {
            TabContent::Loading => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!("Extracting {}...", tab.id));
                });
            }
            TabContent::Error(e) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
                if ui.button("Retry").clicked() {
                    actions.push(Action::RetryTab(tab.id.clone()));
                }
            }
            TabContent::Text(_) => source_view(ui, tab, index, actions),
        }
    }

    // ---- UI: search panel ---------------------------------------------------

    fn search_panel(&mut self, ui: &mut egui::Ui) {
        let strip = ui
            .horizontal_wrapped(|ui| {
                let items = self.search.states.iter().map(|s| (s.title.as_str(), s.running(), ""));
                let strip = tab_strip(ui, items, self.search.active, "close");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Hide").clicked() {
                        self.search.open = false;
                    }
                });
                strip
            })
            .inner;
        if let Some(i) = strip.clicked {
            self.search.active = i;
        }
        if let Some(i) = strip.closed {
            self.actions.push(Action::CloseSearch(i));
        }
        if self.search.states.is_empty() {
            return;
        }
        let active = self.search.active.min(self.search.states.len() - 1);
        self.search.active = active;
        let s = &mut self.search.states[active];
        let actions = &mut self.actions;
        ui.horizontal(|ui| {
            if s.finished {
                ui.label(s.summary());
            } else {
                ui.add(
                    egui::ProgressBar::new(if s.total == 0 { 0.0 } else { s.done as f32 / s.total as f32 })
                        .text(format!("{}/{} DEX, {} hits", s.done, s.total, s.hits))
                        .desired_width(220.0),
                );
                if s.cancelled {
                    ui.label(RichText::new("cancelling...").weak());
                } else if ui.button("Cancel").clicked() {
                    actions.push(Action::CancelSearch(active));
                }
            }
            if s.dropped > 0 {
                ui.label(
                    RichText::new(format!("showing the first {}, {} not kept", s.results.len(), s.dropped))
                        .color(ui.visuals().warn_fg_color),
                )
                .on_hover_text("Raise the row limit in the top bar and search again to keep more");
            }
            ui.separator();
            ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut s.filter).desired_width(220.0));
            if ui.button("Copy").on_hover_text("Copy every kept row in the CLI line format").clicked() {
                actions.push(Action::Copy(s.export()));
            }
        });
        if let Some(e) = &s.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        for e in &s.errors {
            ui.colored_label(ui.visuals().warn_fg_color, format!("not searched: {e}"));
        }
        ui.separator();
        s.refresh_filter();
        let visible = s.visible();
        let row_height = ui.text_style_height(&TextStyle::Monospace);
        egui::ScrollArea::both().auto_shrink([false, false]).show_rows(ui, row_height, visible.len(), |ui, range| {
            for vi in range {
                let i = visible[vi];
                let r = &s.results[i];
                let label = RichText::new(s.line(i)).monospace();
                let resp = ui.add(egui::Label::new(label).sense(egui::Sense::click()).wrap_mode(egui::TextWrapMode::Extend));
                // `Lcls;->name(...)` -> (`Lcls;`, `name(...)`), only when needed.
                let target = || match r.method.split_once("->") {
                    Some((c, m)) => (c.to_string(), Some(Jump::Method(m.to_string()))),
                    None => (r.method.clone(), None),
                };
                if resp.double_clicked() {
                    let (class, jump) = target();
                    actions.push(Action::OpenClass { descriptor: class, jump });
                }
                resp.context_menu(|ui| {
                    let (class, jump) = target();
                    if ui.button(format!("Open {}", r.method)).clicked() {
                        actions.push(Action::OpenClass { descriptor: class.clone(), jump });
                        ui.close();
                    }
                    if ui.button(format!("Open {}", names::dalvik_to_dot(&class))).clicked() {
                        actions.push(Action::open(&class, None));
                        ui.close();
                    }
                    if ui.button("Find references to this class").clicked() {
                        actions.push(Action::find_type(&class));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Copy row").clicked() {
                        actions.push(Action::Copy(r.line()));
                        ui.close();
                    }
                });
            }
        });
    }

    // ---- UI: status bar -----------------------------------------------------

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let last = self.log.back().cloned().unwrap_or_default();
            ui.label(&last).on_hover_ui(|ui| {
                for m in self.log.iter().rev().take(10) {
                    ui.label(RichText::new(m).small());
                }
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.debug {
                    ui.label(RichText::new("[debug]").weak());
                }
                let stats = self.store.engine.cache_stats();
                pill(ui, format!("cache {}/{}", stats.memory_hits + stats.disk_hits, stats.memory_hits + stats.disk_hits + stats.inflates))
                    .on_hover_ui(|ui| {
                        ui.label(format!("memory hits {}\ndisk hits {}\ninflates {}", stats.memory_hits, stats.disk_hits, stats.inflates));
                    });
                if let Some(info) = &self.load_info {
                    pill(ui, format!("{} ms", info.ms)).on_hover_text("time to index every class");
                    pill(ui, format!("{} DEX", info.dex));
                    pill(ui, format!("{} classes", info.classes));
                    if !info.failed.is_empty() {
                        ui.colored_label(ui.visuals().warn_fg_color, format!("{} DEX failed", info.failed.len())).on_hover_ui(|ui| {
                            for f in &info.failed {
                                ui.label(RichText::new(f).small());
                            }
                        });
                    }
                }
                if self.search.any_running() || self.tabs.iter().any(Tab::is_loading) {
                    ui.spinner();
                }
            });
        });
    }
}

/// What the user did to a [`tab_strip`] this frame.
#[derive(Default)]
struct StripResponse {
    clicked: Option<usize>,
    closed: Option<usize>,
}

/// A row of selectable, closable tab titles: `(title, busy, hover text)`.
fn tab_strip<'a>(
    ui: &mut egui::Ui,
    items: impl Iterator<Item = (&'a str, bool, &'a str)>,
    active: usize,
    close_hint: &str,
) -> StripResponse {
    let mut out = StripResponse::default();
    for (i, (title, busy, hover)) in items.enumerate() {
        let selected = i == active;
        let r = if busy { ui.selectable_label(selected, format!("⟳ {title}")) } else { ui.selectable_label(selected, title) };
        let r = if hover.is_empty() { r } else { r.on_hover_text(hover) };
        if r.clicked() {
            out.clicked = Some(i);
        }
        if r.middle_clicked() || ui.small_button("x").on_hover_text(close_hint).clicked() {
            out.closed = Some(i);
        }
        ui.separator();
    }
    out
}

fn pill(ui: &mut egui::Ui, text: String) -> egui::Response {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(6, 1))
        .show(ui, |ui| ui.label(RichText::new(text).small()))
        .response
}

/// How a part of a source line is drawn on top of the line's own style.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// Ctrl is held and Ctrl+click would open the member's declaration.
    Link,
    /// The member under the caret.
    Caret,
}

/// Colours shared by every line of one [`source_view`] pass.
struct LineStyle {
    font: egui::FontId,
    text: Color32,
    link: Color32,
    caret_bg: Color32,
}

/// One source line as a layout job: the line-number `prefix`, then `line`
/// cut at the `marks` boundaries (byte ranges on char boundaries).
fn line_job(prefix: &str, line: &str, bg: Color32, marks: &[(usize, usize, Mark)], st: &LineStyle) -> LayoutJob {
    let base = TextFormat { font_id: st.font.clone(), color: st.text, background: bg, ..Default::default() };
    let mut job = LayoutJob::default();
    job.append(prefix, 0.0, base.clone());
    let mut cuts = vec![0, line.len()];
    for &(s, e, _) in marks {
        cuts.push(s.min(line.len()));
        cuts.push(e.min(line.len()));
    }
    cuts.sort_unstable();
    cuts.dedup();
    for w in cuts.windows(2) {
        let (a, b) = (w[0], w[1]);
        let mut f = base.clone();
        for &(s, e, m) in marks {
            if s <= a && b <= e {
                match m {
                    Mark::Link => {
                        f.color = st.link;
                        f.underline = Stroke::new(1.0_f32, st.link);
                    }
                    Mark::Caret => f.background = st.caret_bg,
                }
            }
        }
        job.append(&line[a..b], 0.0, f);
    }
    job
}

/// The virtualised disassembly / XML view with find highlights, the caret,
/// member links while Ctrl is held and the per-line context menu.
///
/// Lines sense clicks but are not focusable, so a click only places the
/// caret and the `X` shortcut keeps working (see `AscApp::shortcuts`). The
/// view is read-only and shows the text as-is, so a caret column is a plain
/// byte offset into its line.
fn source_view(ui: &mut egui::Ui, tab: &mut Tab, index: Option<&ClassIndex>, actions: &mut Vec<Action>) {
    let row_height = ui.text_style_height(&TextStyle::Monospace);
    let row_stride = row_height + ui.spacing().item_spacing.y;
    let mut scroll = egui::ScrollArea::both().auto_shrink([false, false]);
    if let Some(row) = tab.scroll_to.take() {
        let offset = (row as f32 * row_stride - ui.available_height() / 3.0).max(0.0);
        scroll = scroll.vertical_scroll_offset(offset);
    }
    let current = tab.find_matches.get(tab.find_cursor).copied();
    let jump = tab.jump_line;
    let lines = tab.lines();
    let width = lines.len().max(1).ilog10() as usize + 1;
    let match_bg = ui.visuals().selection.bg_fill;
    let current_bg = Color32::from_rgb(200, 120, 0);
    let jump_bg = match_bg.gamma_multiply(0.5);
    let st = LineStyle {
        font: TextStyle::Monospace.resolve(ui.style()),
        text: ui.visuals().text_color(),
        link: ui.visuals().hyperlink_color,
        caret_bg: ui.visuals().widgets.hovered.weak_bg_fill,
    };
    // The manifest has no members; a class tab's id is its descriptor.
    let class = (tab.id != MANIFEST_TAB).then_some(tab.id.as_str());
    let ctrl = ui.input(|i| i.modifiers.command);
    let linkable = |m: &MemberSpan| !m.declaration && index.is_some_and(|ix| ix.contains(&m.class));
    let mut caret = tab.caret;
    scroll.show_rows(ui, row_height, lines.len(), |ui, range| {
        for i in range {
            let line = &lines[i];
            let bg = if tab.is_find_match(i) {
                if Some(i) == current {
                    current_bg
                } else {
                    match_bg
                }
            } else if Some(i) == jump {
                jump_bg
            } else {
                Color32::TRANSPARENT
            };
            let caret_col = caret.filter(|c| c.0 == i).map(|c| c.1);
            let spans = match class {
                Some(c) if ctrl || caret_col.is_some() => member_spans_in_line(line, c),
                _ => Vec::new(),
            };
            let mut marks = Vec::new();
            if let Some(m) = caret_col.and_then(|col| spans.iter().find(|m| m.contains(col))) {
                marks.push((m.start, m.end, Mark::Caret));
            }
            if ctrl {
                marks.extend(spans.iter().filter(|m| linkable(m)).map(|m| (m.start, m.end, Mark::Link)));
            }
            let prefix = format!("{:>width$}  ", i + 1);
            let galley = ui.fonts_mut(|f| f.layout_job(line_job(&prefix, line, bg, &marks, &st)));
            let resp = ui.add(egui::Label::new(galley.clone()).sense(egui::Sense::CLICK));
            let origin = resp.rect.min;
            // Byte column of `line` under a screen position.
            let col_at = |pos: egui::Pos2| char_to_byte(line, galley.cursor_from_pos(pos - origin).index.saturating_sub(prefix.len()));
            if let Some(col) = caret_col {
                let x = galley.pos_from_cursor(CCursor::new(prefix.len() + line[..col.min(line.len())].chars().count())).min.x;
                ui.painter().vline(origin.x + x, resp.rect.y_range(), Stroke::new(1.5_f32, st.text));
            }
            if ctrl {
                let hovered = resp.hover_pos().zip(class).and_then(|(p, c)| member_at(line, c, col_at(p)));
                if hovered.is_some_and(|m| linkable(&m)) {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
            }
            if resp.clicked() {
                if let Some(pos) = resp.interact_pointer_pos() {
                    let col = col_at(pos);
                    caret = Some((i, col));
                    if ctrl {
                        if let Some(m) = class.and_then(|c| member_at(line, c, col)).filter(|m| !m.declaration) {
                            actions.push(Action::GotoMember(m));
                        }
                    }
                }
            }
            resp.context_menu(|ui| line_menu(ui, line, class.unwrap_or_default(), index, actions));
        }
    });
    tab.caret = caret;
}

/// Status message for a jump whose declaration is not in class `descriptor`.
fn unresolved_note(descriptor: &str, jump: &Jump) -> String {
    match jump {
        Jump::Method(m) => format!("{m} is not declared in {descriptor}"),
        Jump::Member { name, .. } => format!("Declaration not found: {}->{name}", names::dalvik_to_dot(descriptor)),
    }
}

fn line_menu(ui: &mut egui::Ui, line: &str, class: &str, index: Option<&ClassIndex>, actions: &mut Vec<Action>) {
    let mut any = false;
    for d in descriptors_in_line(line) {
        let dotted = names::dalvik_to_dot(&d);
        if index.is_some_and(|ix| ix.contains(&d)) && ui.button(format!("Open {dotted}")).clicked() {
            actions.push(Action::open(&d, None));
            ui.close();
        }
        if ui.button(format!("Find references to {dotted}")).clicked() {
            actions.push(Action::find_type(&d));
            ui.close();
        }
        any = true;
    }
    let spans = member_spans_in_line(line, class);
    let mut seen: Vec<&MemberSpan> = Vec::new();
    for m in &spans {
        if seen.iter().any(|s| (s.kind, &s.class, &s.name, &s.descriptor) == (m.kind, &m.class, &m.name, &m.descriptor)) {
            continue;
        }
        seen.push(m);
        let linkable = !m.declaration && index.is_some_and(|ix| ix.contains(&m.class));
        if linkable && ui.button(format!("Go to {}->{}", short_name(&m.class), m.name)).on_hover_text("Ctrl+click").clicked() {
            actions.push(Action::GotoMember(m.clone()));
            ui.close();
        }
        if ui.button(format!("Find references to {}->{}", short_name(&m.class), m.name)).on_hover_text("X").clicked() {
            actions.push(Action::find_member(m));
            ui.close();
        }
        any = true;
    }
    if let Some(s) = const_string_in_line(line) {
        let shown: String = s.chars().take(40).collect();
        let label = if shown.len() < s.len() {
            format!("Find string references \"{shown}…\"")
        } else {
            format!("Find string references \"{shown}\"")
        };
        if ui.button(label).clicked() {
            actions.push(Action::Search {
                kind: SearchKind::String,
                value: regex_escape(&s),
                class: String::new(),
                fuzzy: false,
                exact: false,
            });
            ui.close();
        }
        any = true;
    }
    if any {
        ui.separator();
    }
    if ui.button("Copy line").clicked() {
        actions.push(Action::Copy(line.trim_end().to_string()));
        ui.close();
    }
}

fn render_class(ui: &mut egui::Ui, c: ClassEntry<'_>, actions: &mut Vec<Action>, selected: Option<&str>, full: bool) {
    let label = if full { names::dalvik_to_dot(c.descriptor) } else { short_name(c.descriptor) };
    let is_selected = selected == Some(c.descriptor);
    let r = ui.selectable_label(is_selected, label).on_hover_ui(|ui| {
        ui.label(format!("{}  [{}]", c.descriptor, c.dex_name));
    });
    if r.clicked() {
        actions.push(Action::open(c.descriptor, None));
    }
    r.context_menu(|ui| class_menu(ui, c.descriptor, actions));
}

fn class_menu(ui: &mut egui::Ui, descriptor: &str, actions: &mut Vec<Action>) {
    if ui.button("Open").clicked() {
        actions.push(Action::open(descriptor, None));
        ui.close();
    }
    if ui.button("Find references to this class").clicked() {
        actions.push(Action::find_type(descriptor));
        ui.close();
    }
    if ui.button("Find calls to its methods").clicked() {
        actions.push(Action::Search {
            kind: SearchKind::Method,
            value: String::new(),
            class: descriptor.to_string(),
            fuzzy: false,
            exact: false,
        });
        ui.close();
    }
    if ui.button("Find accesses to its fields").clicked() {
        actions.push(Action::Search {
            kind: SearchKind::Field,
            value: String::new(),
            class: descriptor.to_string(),
            fuzzy: false,
            exact: false,
        });
        ui.close();
    }
    ui.separator();
    if ui.button("Copy descriptor").clicked() {
        actions.push(Action::Copy(descriptor.to_string()));
        ui.close();
    }
    if ui.button("Copy class name").clicked() {
        actions.push(Action::Copy(names::dalvik_to_dot(descriptor)));
        ui.close();
    }
}

/// Package tree. `CollapsingHeader` lays out a body only while it is open, so
/// closed packages cost one header each; the counts are precomputed.
fn render_package(ui: &mut egui::Ui, node: Package<'_>, path: &str, actions: &mut Vec<Action>, selected: Option<&str>) {
    for child in node.children() {
        let name = child.name();
        let full = if path.is_empty() { name.to_string() } else { format!("{path}/{name}") };
        // Collapse single-child chains (com -> example -> app) into one header.
        let (label, target) = collapse_chain(child);
        egui::CollapsingHeader::new(format!("{label}  ({})", target.count())).id_salt(&full).show(ui, |ui| {
            render_package(ui, target, &full, actions, selected);
        });
    }
    for c in node.classes() {
        render_class(ui, c, actions, selected, false);
    }
}

fn collapse_chain(node: Package<'_>) -> (String, Package<'_>) {
    let mut label = node.name().to_string();
    let mut cur = node;
    while cur.classes().len() == 0 && cur.children().len() == 1 {
        let next = cur.children().next().unwrap();
        label.push('.');
        label.push_str(next.name());
        cur = next;
    }
    (label, cur)
}

impl eframe::App for AscApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
        self.shortcuts(ctx);
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(4.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));
        egui::SidePanel::left("classes").default_width(320.0).min_width(200.0).show(ctx, |ui| self.class_tree(ui));
        if self.search.open && !self.search.states.is_empty() {
            egui::TopBottomPanel::bottom("search").resizable(true).default_height(260.0).min_height(120.0).show(ctx, |ui| {
                ui.add_space(2.0);
                self.search_panel(ui);
            });
        }
        egui::CentralPanel::default().show(ctx, |ui| self.editor(ui));
        self.apply_actions();
        // No repaint timer: every worker event calls `request_repaint`, and
        // the spinners shown while something is busy re-request it themselves.
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.prefs.save(storage);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Workers hold their own `Arc<Engine>`, so `Engine::drop` may never run
        // before the process exits; land queued disk-cache writes here and stop
        // a still-running search from starting a writer that exit would kill.
        self.store.engine.close_cache_writes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLS: &str = "Lcom/x/Foo;";
    const TEXT: &str = ".class Lcom/x/Foo;\n.method public run()V\n    invoke-static {}, Lcom/x/Bar;->go()V\n.end method";

    /// An app over a missing APK: the index load and every search fail in
    /// the background, and as their events are never drained here a search
    /// stays "running" for the whole test.
    fn app() -> AscApp {
        let apk = PathBuf::from("/nonexistent/asc-gui-test.apk");
        let cache = asc_engine::CacheConfig { memory_bytes: 64 << 20, ..Default::default() };
        AscApp::with_context(egui::Context::default(), Prefs::default(), apk, 1, false, cache)
    }

    fn with_class_tab(text: &str) -> AscApp {
        let mut app = app();
        let mut tab = Tab::loading(CLS.into(), "Foo".into(), CLS.into());
        tab.set_text(text);
        app.tabs.push(tab);
        app.active = 0;
        app
    }

    fn key_x(repeat: bool) -> egui::Event {
        egui::Event::Key { key: Key::X, physical_key: None, pressed: true, repeat, modifiers: Modifiers::NONE }
    }

    /// One frame that only runs the shortcuts, then applies the actions.
    fn frame(app: &mut AscApp, events: Vec<egui::Event>) {
        let ctx = app.store.ctx.clone();
        let _ = ctx.run(egui::RawInput { events, ..Default::default() }, |ctx| app.shortcuts(ctx));
        app.apply_actions();
    }

    fn titles(app: &AscApp) -> Vec<&str> {
        app.search.states.iter().map(|s| s.title.as_str()).collect()
    }

    fn caret_on_go(app: &mut AscApp) {
        app.tabs[0].caret = Some((2, TEXT.lines().nth(2).unwrap().find("go").unwrap()));
    }

    #[test]
    fn held_x_starts_one_search() {
        let mut app = with_class_tab(TEXT);
        caret_on_go(&mut app);
        frame(&mut app, vec![key_x(false)]);
        assert_eq!(titles(&app), vec!["method: Lcom/x/Bar;->go (exact)"]);
        let already = |app: &AscApp| app.log.iter().filter(|m| m.starts_with("Already searching")).count();
        // Auto-repeat while the key is held does not even ask for a search.
        frame(&mut app, vec![key_x(true), key_x(true)]);
        frame(&mut app, vec![key_x(true)]);
        assert_eq!((app.search.states.len(), already(&app)), (1, 0));
        // A fresh press while the same search still runs reuses it.
        let release = egui::Event::Key { key: Key::X, physical_key: None, pressed: false, repeat: false, modifiers: Modifiers::NONE };
        frame(&mut app, vec![release]);
        frame(&mut app, vec![key_x(false)]);
        assert_eq!((app.search.states.len(), already(&app)), (1, 1));
    }

    #[test]
    fn member_xref_is_exact_for_that_search_only() {
        let mut app = with_class_tab(TEXT);
        caret_on_go(&mut app);
        frame(&mut app, vec![key_x(false)]);
        assert!(!app.exact_name, "the exact-name box is left as the user set it");
        assert_eq!((app.search_value.as_str(), app.search_class.as_str()), ("go", "Lcom/x/Bar;"));
        // Submitting the top bar again is a regex / substring search.
        app.actions.push(Action::Search {
            kind: app.prefs.search_kind,
            value: app.search_value.clone(),
            class: app.search_class.clone(),
            fuzzy: app.prefs.fuzzy_class,
            exact: app.exact_name,
        });
        app.apply_actions();
        assert_eq!(titles(&app), vec!["method: Lcom/x/Bar;->go (exact)", "method: Lcom/x/Bar;->go"]);
    }

    #[test]
    fn x_right_after_a_jump_finds_the_declared_member() {
        let mut app = with_class_tab(TEXT);
        app.tabs[0].caret = Some((2, 4));
        app.actions.push(Action::GotoMember(MemberSpan {
            start: 0,
            end: 0,
            kind: MemberKind::Method,
            class: CLS.into(),
            name: "run".into(),
            descriptor: "()V".into(),
            declaration: false,
        }));
        app.apply_actions();
        assert_eq!(app.tabs[0].caret, Some((1, ".method public ".len())));
        frame(&mut app, vec![key_x(false)]);
        assert_eq!(titles(&app), vec!["method: Lcom/x/Foo;->run (exact)"]);
    }

    #[test]
    fn reopening_a_loading_class_keeps_the_pending_jump() {
        let mut app = app();
        let jump = Jump::Member { kind: MemberKind::Method, name: "go".into(), descriptor: "()V".into() };
        app.open_class("Lcom/x/Bar;", Some(jump.clone()));
        assert!(app.tabs[0].is_loading());
        // e.g. the class picked again in the tree while it is extracted
        app.open_class("com.x.Bar", None);
        assert_eq!(app.tabs[0].pending_jump, Some(jump.clone()));
        app.tabs[0].set_error("boom".into());
        app.open_class("Lcom/x/Bar;", None);
        assert!(app.tabs[0].is_loading());
        assert_eq!(app.tabs[0].pending_jump, Some(jump));
        let other = Jump::Method("other".into());
        app.open_class("Lcom/x/Bar;", Some(other.clone()));
        assert_eq!(app.tabs[0].pending_jump, Some(other));
        assert_eq!(app.tabs.len(), 1);
    }
}
