//! Two packages whose records request each other across the package
//! boundary, for tests of how module requests are resolved:
//!
//! - the `entry` package ([`packaged_entry_program`]):
//!   - [`PACKAGED_INDEX`] `pages/Index` calls five imports: `tool` of
//!     [`PACKAGED_TOOL`] *in module `lib`* (the request names the module),
//!     `kit` of the package `kit` and `own` of the package `@scope/own`
//!     (requests that are a package name, which
//!     [`PACKAGED_ENTRY_PKG_CONTEXT`] leads to an entry file), `gone` of
//!     the package `absent` (not in that table) and `spare` of
//!     [`PACKAGED_TOOL`] in a module the program does not have;
//!   - its own copy of [`PACKAGED_TOOL`], with `tool` and `spare`: a
//!     library packed into both packages;
//!   - [`PACKAGED_OWN`], the entry file of `@scope/own`, with `own`;
//! - the `lib` package ([`packaged_library_program`]): [`PACKAGED_TOOL`]
//!   with `tool` and `spare`, and [`PACKAGED_KIT`], the entry file of
//!   `kit`, with `kit`.

use super::{AbcBuilder, AbcCode, AbcFunction, AbcModule, AbcRecord, Asm, Op};
use asc_abc::FunctionKind;

pub const PACKAGED_INDEX: &str = "&entry/src/main/ets/pages/Index&";
pub const PACKAGED_TOOL: &str = "&shared/src/main/ets/Tool&1.0.0";
pub const PACKAGED_OWN: &str = "&@scope/own/Index&2.0.0";
pub const PACKAGED_KIT: &str = "&kit/src/main/ets/Main&1.0.0";

/// `module.json` of the `entry` package.
pub const PACKAGED_ENTRY_MODULE_JSON: &str = r#"{
  "app": { "bundleName": "com.example.sample", "versionCode": 1000000, "versionName": "1.0.0" },
  "module": { "name": "entry", "type": "entry", "deviceTypes": ["phone"] }
}
"#;

/// `module.json` of the `lib` package.
pub const PACKAGED_LIBRARY_MODULE_JSON: &str = r#"{
  "app": { "bundleName": "com.example.sample", "versionCode": 1000000, "versionName": "1.0.0" },
  "module": { "name": "lib", "type": "shared", "deviceTypes": ["phone"] }
}
"#;

/// `pkgContextInfo.json` of the `entry` package: `kit` lives in module
/// `lib`, `@scope/own` in the package itself, and a native library has no
/// entry file.
pub const PACKAGED_ENTRY_PKG_CONTEXT: &str = r#"{
  "kit": { "packageName": "kit", "bundleName": "", "moduleName": "lib", "version": "1.0.0", "entryPath": "src/main/ets/Main.ets", "isSO": false, "dependencyAlias": "" },
  "@scope/own": { "packageName": "@scope/own", "bundleName": "", "moduleName": "", "version": "2.0.0", "entryPath": "Index.ets", "isSO": false, "dependencyAlias": "" },
  "libnative.so": { "packageName": "libnative.so", "bundleName": "", "moduleName": "", "version": "", "entryPath": "", "isSO": true, "dependencyAlias": "" }
}
"#;

fn function(name: &str, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(0, 3, asm)).kind(FunctionKind::FUNCTION)
}

/// A record that exports the functions `names`, each a `#*#name` that only
/// returns.
fn exporting(record: &str, package: &str, names: &[&str]) -> AbcRecord {
    let mut module = AbcModule::new();
    let mut main = Asm::new();
    for (index, name) in names.iter().enumerate() {
        module = module.export(name, name);
        let index = u8::try_from(index).expect("a handful of exports");
        main.op("definefunc", [0.into(), Op::method(&format!("#*#{name}")), 0.into()]).op("stmodulevar", [index.into()]);
    }
    main.op("returnundefined", []);
    let mut out = AbcRecord::ets_module(record, package, &[], module).function(function("func_main_0", main));
    for name in names {
        let mut body = Asm::new();
        body.op("returnundefined", []);
        out = out.function(function(&format!("#*#{name}"), body));
    }
    out
}

/// The code of the `entry` package.
pub fn packaged_entry_program() -> AbcBuilder {
    let module = AbcModule::new()
        .import("tool", "tool", &format!("@normalized:N&lib&{PACKAGED_TOOL}"))
        .import("kit", "kit", "kit")
        .import("own", "own", "@scope/own")
        .import("gone", "gone", "absent")
        .import("spare", "spare", &format!("@normalized:N&elsewhere&{PACKAGED_TOOL}"));
    let mut main = Asm::new();
    for index in 0..5u8 {
        main.op("ldexternalmodulevar", [index.into()]).op("callarg0", [0.into()]);
    }
    main.op("returnundefined", []);
    let mut builder = AbcBuilder::new();
    builder
        .record(AbcRecord::ets_module(PACKAGED_INDEX, "entry", &[], module).function(function("func_main_0", main)))
        .record(exporting(PACKAGED_TOOL, "shared", &["tool", "spare"]))
        .record(exporting(PACKAGED_OWN, "@scope/own", &["own"]));
    builder
}

/// The code of the `lib` package.
pub fn packaged_library_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    builder.record(exporting(PACKAGED_TOOL, "shared", &["tool", "spare"])).record(exporting(PACKAGED_KIT, "kit", &["kit"]));
    builder
}
