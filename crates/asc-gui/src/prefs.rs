//! Preferences that survive restarts. Stored as plain strings through eframe's
//! storage; egui persists panel sizes and the theme preference on its own.

use crate::search::SearchKind;

/// Row-limit choices for search results; `0` is unlimited.
pub const ROW_CAPS: [usize; 4] = [1000, 5000, 20000, 0];

pub fn row_cap_label(cap: usize) -> String {
    if cap == 0 {
        "unlimited".to_string()
    } else {
        cap.to_string()
    }
}

pub struct Prefs {
    pub search_kind: SearchKind,
    pub fuzzy_class: bool,
    pub row_cap: usize,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { search_kind: SearchKind::String, fuzzy_class: false, row_cap: 5000 }
    }
}

const KIND: &str = "asc.search_kind";
const FUZZY: &str = "asc.fuzzy_class";
const ROW_CAP: &str = "asc.row_cap";

impl Prefs {
    pub fn load(storage: Option<&dyn eframe::Storage>) -> Prefs {
        let mut p = Prefs::default();
        let Some(s) = storage else { return p };
        if let Some(k) = s.get_string(KIND).and_then(|v| SearchKind::parse(&v)) {
            p.search_kind = k;
        }
        if let Some(v) = s.get_string(FUZZY) {
            p.fuzzy_class = v == "true";
        }
        if let Some(v) = s.get_string(ROW_CAP).and_then(|v| v.parse().ok()) {
            if ROW_CAPS.contains(&v) {
                p.row_cap = v;
            }
        }
        p
    }

    pub fn save(&self, storage: &mut dyn eframe::Storage) {
        storage.set_string(KIND, self.search_kind.as_str().to_string());
        storage.set_string(FUZZY, self.fuzzy_class.to_string());
        storage.set_string(ROW_CAP, self.row_cap.to_string());
    }

    /// Effective cap for a new search.
    pub fn cap(&self) -> usize {
        if self.row_cap == 0 {
            usize::MAX
        } else {
            self.row_cap
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::Storage;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemStorage(HashMap<String, String>);

    impl eframe::Storage for MemStorage {
        fn get_string(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn set_string(&mut self, key: &str, value: String) {
            self.0.insert(key.to_string(), value);
        }
        fn flush(&mut self) {}
    }

    #[test]
    fn save_then_load_round_trips() {
        let mut storage = MemStorage::default();
        let p = Prefs { search_kind: SearchKind::Field, fuzzy_class: true, row_cap: 20000 };
        p.save(&mut storage);
        let back = Prefs::load(Some(&storage));
        assert_eq!(back.search_kind, SearchKind::Field);
        assert!(back.fuzzy_class);
        assert_eq!(back.row_cap, 20000);
        assert_eq!(back.cap(), 20000);
    }

    #[test]
    fn bad_or_missing_values_fall_back_to_defaults() {
        let d = Prefs::default();
        let none = Prefs::load(None);
        assert_eq!((none.search_kind, none.fuzzy_class, none.row_cap), (d.search_kind, d.fuzzy_class, d.row_cap));
        let mut storage = MemStorage::default();
        storage.set_string(KIND, "nope".into());
        storage.set_string(ROW_CAP, "123".into());
        let p = Prefs::load(Some(&storage));
        assert_eq!(p.search_kind, d.search_kind);
        assert_eq!(p.row_cap, d.row_cap);
        let unlimited = Prefs { row_cap: 0, ..Prefs::default() };
        assert_eq!(unlimited.cap(), usize::MAX);
    }
}
