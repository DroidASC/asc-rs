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
            asc_ark_engine::Format::detect(spec).is_some()
        } else {
            asc_ark_engine::Format::accepts(spec) && !has_dex(spec)
        };
        if harmony {
            ProgramFormat::Harmony
        } else {
            ProgramFormat::Android
        }
    }
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
