//! egui-based APK browser.
//!
//! Layout: a package/class tree on the left (with a filter box), a tabbed
//! disassembly view in the centre, a reference-search bar on top and a
//! search-history panel at the bottom. Everything heavy (class enumeration,
//! class extraction, reference search) runs on background threads and reports
//! back through a channel; the UI never blocks. Panel sizes, theme and search
//! preferences persist across runs.

mod app;
mod members;
mod prefs;
mod search;
mod store;
mod tabs;

use std::path::PathBuf;

/// Open the browser window for `apk`.
pub fn launch(apk: PathBuf, threads: usize, debug: bool, cache: bool) -> Result<(), String> {
    let title = format!("Droid ASC - {}", apk.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 820.0]).with_title(&title).with_app_id("droidasc"),
        ..Default::default()
    };
    // The app name doubles as the storage key, so it must not vary with the APK.
    eframe::run_native("droidasc", options, Box::new(move |cc| Ok(Box::new(app::AscApp::new(cc, apk, threads, debug, cache)))))
        .map_err(|e| e.to_string())
}
