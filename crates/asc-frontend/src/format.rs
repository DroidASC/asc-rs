//! Which engine answers for a program: the one rule the `asc` commands,
//! the daemon and the MCP tools go by.

use std::path::Path;

/// The format of a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramFormat {
    /// DEX code: an APK, a jar, a `.dex`, or several of them.
    Android,
    /// ArkCompiler bytecode: a `.hap` / `.hsp`, an `.app`, a `.abc`, or several of them.
    Harmony,
}

impl ProgramFormat {
    /// The format of the program at `spec` (a file, a directory, or paths
    /// joined with `,`). A HarmonyOS program is a HarmonyOS file, or a
    /// directory / list that holds HarmonyOS files and no DEX code: a program
    /// with both stays a DEX program, as it was before HarmonyOS files meant
    /// anything ([`left_out_note`] says so). Anything that is not
    /// recognizably HarmonyOS is a DEX program, whose engine reports what is
    /// wrong with it.
    pub fn of(spec: &Path) -> ProgramFormat {
        let harmony = if spec.is_file() {
            !is_android_name(spec) && asc_ark_engine::Format::detect(spec).is_some()
        } else {
            asc_ark_engine::Format::accepts(spec) && !has_dex(spec)
        };
        if harmony { ProgramFormat::Harmony } else { ProgramFormat::Android }
    }
}

/// A file whose name says DEX code. Such a file is not opened to look for
/// HarmonyOS content: reading the directory of a large APK costs about a
/// millisecond, on every command, to rule out what its name already does.
fn is_android_name(file: &Path) -> bool {
    file.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| ["apk", "dex", "jar", "aar", "apex"].iter().any(|known| extension.eq_ignore_ascii_case(known)))
}

/// Whether the DEX engine finds code under `spec`.
fn has_dex(spec: &Path) -> bool {
    asc_engine::Engine::new(spec).dex_entries().is_ok_and(|entries| !entries.is_empty())
}

/// For a DEX program of several files: the note that its HarmonyOS files are
/// not part of it.
pub fn left_out_note(spec: &Path) -> Option<&'static str> {
    (!spec.is_file() && asc_ark_engine::Format::accepts(spec)).then_some(
        "HarmonyOS files (.hap, .hsp, .app, .abc) of this program are left out next to its DEX code; query them by their own path",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_named_as_dex_code_is_not_opened_to_look_for_more() {
        for name in ["app.apk", "classes.dex", "lib.JAR", "base.aar", "com.android.art.apex"] {
            assert!(is_android_name(Path::new(name)), "{name}");
        }
        for name in ["entry.hap", "shop.app", "modules.abc", "bundle.zip", "apk", "noextension"] {
            assert!(!is_android_name(Path::new(name)), "{name}");
        }
        // No such file: nothing is read, and the answer is the DEX engine's to give.
        assert_eq!(ProgramFormat::of(Path::new("/nonexistent/app.apk")), ProgramFormat::Android);
    }
}
