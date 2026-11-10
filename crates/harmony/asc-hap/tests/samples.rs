//! Real packages, when they are on this machine: `<workspace>/../ark/ReArk/samples`
//! (or `$ASC_ABC_SAMPLES`) and the app-store `entry.hap` in
//! `$ASC_ABC_LARGE_SAMPLE`. Each test passes vacuously when its files are absent.

use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use asc_hap::{ModuleJson, PackInfo, PkgContextInfo};
use zip::ZipArchive;

/// `$ASC_ABC_SAMPLES`, else `<workspace>/../ark/ReArk/samples`.
fn samples() -> Option<PathBuf> {
    let path = match std::env::var_os("ASC_ABC_SAMPLES") {
        Some(path) => PathBuf::from(path),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../ark/ReArk/samples"),
    };
    path.is_dir().then_some(path)
}

/// `$ASC_ABC_LARGE_SAMPLE`: the directory of an app-store `entry.hap`. No default.
fn large_sample_dir() -> Option<PathBuf> {
    std::env::var_os("ASC_ABC_LARGE_SAMPLE").map(PathBuf::from).filter(|path| path.is_dir())
}

fn entry<R: Read + Seek>(zip: &mut ZipArchive<R>, name: &str) -> Option<Vec<u8>> {
    let mut file = zip.by_name(name).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    Some(bytes)
}

/// The metadata of one HAP.
struct Package {
    module: ModuleJson,
    pack: PackInfo,
    packages: Option<PkgContextInfo>,
}

impl Package {
    fn read<R: Read + Seek>(mut zip: ZipArchive<R>) -> Package {
        Package {
            module: ModuleJson::parse(&entry(&mut zip, "module.json").expect("module.json")).unwrap(),
            pack: PackInfo::parse(&entry(&mut zip, "pack.info").expect("pack.info")).unwrap(),
            packages: entry(&mut zip, "pkgContextInfo.json").map(|bytes| PkgContextInfo::parse(&bytes).unwrap()),
        }
    }

    /// A `.hap`, or the `entry-default.hap` inside an `.app`.
    fn open(path: &Path) -> Option<Package> {
        let mut zip = ZipArchive::new(File::open(path).ok()?).unwrap();
        if path.extension().is_some_and(|e| e == "app") {
            PackInfo::parse(&entry(&mut zip, "pack.info").expect("pack.info of the .app")).unwrap();
            let hap = entry(&mut zip, "entry-default.hap").expect("entry-default.hap");
            return Some(Package::read(ZipArchive::new(Cursor::new(hap)).unwrap()));
        }
        Some(Package::read(zip))
    }

    fn sample(name: &str) -> Option<Package> {
        Package::open(&samples()?.join(name))
    }

    fn large_sample() -> Option<Package> {
        Package::open(&large_sample_dir()?.join("entry.hap"))
    }

    /// Nothing skipped, nothing left unmodelled except `expected`, and the
    /// two descriptions of the package agree with each other.
    fn check(&self, expected_unmodelled: &[&str]) {
        assert!(self.module.notes.is_empty(), "{:?}", self.module.notes);
        assert_eq!(self.module.unmodelled, expected_unmodelled);
        assert!(self.pack.notes.is_empty() && self.pack.unmodelled.is_empty(), "{:?} {:?}", self.pack.notes, self.pack.unmodelled);
        if let Some(packages) = &self.packages {
            assert!(packages.notes.is_empty() && packages.unmodelled.is_empty(), "{:?} {:?}", packages.notes, packages.unmodelled);
            assert!(packages.packages().iter().all(|p| p.name == p.package_name));
        }
        assert_eq!(self.module.app.bundle_name, self.pack.app.bundle_name);
        assert_eq!(self.module.app.version_code, self.pack.app.version_code);
        let module = &self.pack.modules[0];
        assert_eq!(self.module.module.name, module.name);
        assert_eq!(self.module.app.min_api_version.map(|v| v.level()), module.api_compatible);
        assert_eq!(self.module.app.target_api_version.map(|v| v.level()), module.api_target);
        let names = |abilities: &[asc_hap::Ability]| abilities.iter().map(|a| a.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&self.module.module.abilities), module.abilities.iter().map(|a| a.name.clone()).collect::<Vec<_>>());
        assert_eq!(
            names(&self.module.module.extension_abilities),
            module.extension_abilities.iter().map(|a| a.name.clone()).collect::<Vec<_>>()
        );
        // Both texts are deterministic and the pretty one is the same document.
        assert_eq!(self.module.summary(), self.module.summary());
        assert_eq!(&serde_json::from_str::<serde_json::Value>(&self.module.pretty()).unwrap(), self.module.raw());
    }

    fn exported(&self) -> Vec<&str> {
        self.module.components().filter(|a| a.is_exported()).filter_map(|a| a.name.as_deref()).collect()
    }
}

#[test]
fn every_sample_parses_cleanly() {
    let Some(samples) = samples() else { return };
    let mut seen = 0;
    for file in std::fs::read_dir(samples).unwrap() {
        let path = file.unwrap().path();
        if !path.extension().is_some_and(|e| e == "hap" || e == "app") {
            continue;
        }
        let package = Package::open(&path).unwrap();
        // The module descriptor of every sample is fully modelled.
        package.check(&[]);
        assert_eq!(package.exported(), ["EntryAbility"], "{}", path.display());
        seen += 1;
    }
    assert!(seen >= 6, "only {seen} samples in the directory");
}

#[test]
fn bridge() {
    let Some(p) = Package::sample("Bridge.hap") else { return };
    assert_eq!(p.module.app.bundle_name.as_deref(), Some("com.hmos.exam5.pkg"));
    assert_eq!(p.module.app.debug, Some(true));
    assert_eq!(p.module.app.min_api_version.unwrap().to_string(), "60000020(20)");
    assert!(p.module.module.request_permissions.is_empty() && p.module.module.extension_abilities.is_empty());
    assert!(p.packages.is_none());
    let entry = &p.module.module.abilities[0];
    assert!(entry.deep_links().is_empty());
    // No package table: the record is spelled with the bundle name.
    let names = p.module.record_names(entry.src_entry.as_deref().unwrap(), p.packages.as_ref());
    assert_eq!(names.candidates()[0], "com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility");
}

#[test]
fn contacts() {
    let Some(p) = Package::sample("contacts.hap") else { return };
    assert_eq!(p.module.app.bundle_name.as_deref(), Some("com.example.myapplication"));
    assert_eq!(p.module.module.request_permissions.len(), 1);
    assert_eq!(p.module.module.request_permissions[0].name.as_deref(), Some("ohos.permission.INTERNET"));
    let backup = &p.module.module.extension_abilities[0];
    assert_eq!(
        (backup.name.as_deref(), backup.extension_type.as_deref(), backup.exported),
        (Some("EntryBackupAbility"), Some("backup"), Some(false))
    );
    assert_eq!(backup.metadata[0].resource.as_deref(), Some("$profile:backup_config"));

    let packages = p.packages.as_ref().unwrap();
    assert_eq!(packages.packages().len(), 6);
    assert_eq!(packages.get("@ohos/crypto-js").unwrap().entry_record_name().as_deref(), Some("&@ohos/crypto-js/index&2.0.0"));
    // Both are record names of the sample's modules.abc.
    let owner = packages.locate("&@ohos/jsonwebtoken/src/main/ets/dist/jsonwebtoken&1.0.1").unwrap();
    assert_eq!((owner.package.name.as_str(), owner.path), ("@ohos/jsonwebtoken", "src/main/ets/dist/jsonwebtoken"));
    let names = p.module.record_names(backup.src_entry.as_deref().unwrap(), Some(packages));
    assert_eq!(names.candidates()[0], "&entry/src/main/ets/entrybackupability/EntryBackupAbility&");
}

#[test]
fn easy_hap_is_an_api_9_package() {
    let Some(p) = Package::sample("EasyHap-default-unsigned.app") else { return };
    assert_eq!(p.module.app.bundle_name.as_deref(), Some("com.zjuctf2024.easyhap"));
    assert_eq!(p.module.app.min_api_version.unwrap().to_string(), "9");
    assert_eq!((p.module.app.debug, p.module.app.bundle_type.as_deref(), p.module.module.package_name.as_deref()), (None, None, None));
    let entry = &p.module.module.abilities[0];
    assert_eq!(entry.src_entry.as_deref(), Some("./ets/entryability/EntryAbility.ts"));
    assert_eq!(
        p.module.record_names("./ets/entryability/EntryAbility.ts", None).candidates()[0],
        "com.zjuctf2024.easyhap/entry/ets/entryability/EntryAbility"
    );
}

#[test]
fn fpt_lists_a_native_library() {
    let Some(p) = Package::sample("fpt-default-signed.app") else { return };
    assert_eq!(p.module.app.bundle_name.as_deref(), Some("com.koishi.fpt"));
    assert_eq!(p.module.app.build_mode.as_deref(), Some("release"));
    let packages = p.packages.as_ref().unwrap();
    let native: Vec<_> = packages.packages().iter().filter(|p| p.is_so).map(|p| p.name.as_str()).collect();
    assert_eq!(native, ["libcrypto.so"]);
    assert_eq!(packages.get("entry").unwrap().entry_path, "src/main/");
}

#[test]
fn shctf() {
    let Some(p) = Package::sample("shctf.app") else { return };
    assert_eq!(p.module.app.bundle_name.as_deref(), Some("com.welcome.shctf"));
    assert_eq!(p.module.app.api_release_type.as_deref(), Some("Beta3"));
    assert_eq!(p.module.module.device_types, ["phone"]);
}

/// A store package: a release build with permissions, deep links, an
/// extension and a package table of hundreds of entries.
#[test]
fn large_sample() {
    let Some(p) = Package::large_sample() else { return };
    p.check(&[]);
    let m = &p.module;
    assert_eq!(m.app.debug, Some(false));
    assert!(m.app.bundle_name.is_some() && m.app.version_name.is_some() && m.app.version_code.is_some());
    assert!(m.module.request_permissions.iter().all(|p| p.name.is_some()));
    assert!(!m.module.request_permissions.is_empty());

    let exported = p.exported();
    assert!(!exported.is_empty());
    let summary = m.summary();
    let mut links = 0;
    for ability in m.components() {
        let name = ability.name.as_deref().unwrap();
        let kind = if ability.extension_type.is_some() { "extension" } else { "ability" };
        let line = summary.lines().find(|line| line.starts_with(&format!("{kind} {name} "))).unwrap_or_else(|| panic!("{name}: {summary}"));
        assert_eq!(line.contains(" exported=true "), exported.contains(&name), "{line}");
        assert!(line.contains(&format!(" skills={} ", ability.skills.len())), "{line}");
        // A deep link is a URL pattern, and the summary has one line for each.
        for link in ability.deep_links() {
            assert!(link.contains("://"), "{link}");
            assert!(summary.contains(&format!("deeplink {name} {link}\n")), "{link}");
            links += 1;
        }
    }
    assert!(links > 0);
    assert_eq!(summary.lines().filter(|line| line.starts_with("deeplink ")).count(), links);

    let packages = p.packages.as_ref().unwrap();
    let native = packages.packages().iter().filter(|p| p.is_so).count();
    assert!(0 < native && native < packages.packages().len());
    // With a package table, sources are named by normalized record names.
    let sources = m.components().filter_map(|a| a.src_entry.as_deref()).chain(m.module.src_entry.as_deref());
    for source in sources {
        let names = m.record_names(source, Some(packages));
        let first = &names.candidates()[0];
        assert!(first.starts_with('&') && first.ends_with('&') && !first.contains("./"), "{source}: {first}");
    }
    // The entry record of a package is a record of that package.
    let mut located = 0;
    for package in packages.packages().iter().filter(|p| !p.is_so) {
        let Some(record) = package.entry_record_name() else { continue };
        let owner = packages.locate(&record).unwrap_or_else(|| panic!("{record}"));
        assert_eq!(owner.package.name, package.name, "{record}");
        located += 1;
    }
    assert!(located > 0);
}

/// `ASC_HAP_PRINT=1 cargo test -p asc-hap --test samples print -- --nocapture`
#[test]
fn print_summaries() {
    if std::env::var_os("ASC_HAP_PRINT").is_none() {
        return;
    }
    for package in [Package::large_sample(), Package::sample("contacts.hap")].into_iter().flatten() {
        print!("{}\n{}\n", package.module.summary(), package.pack.summary());
    }
}
