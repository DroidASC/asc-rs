//! resources.arsc queries, resolved XML and the manifest summary against
//! the synthetic audit APK of `asc_fixture::res`.

use asc_engine::{Engine, ResourceField};
use asc_fixture::res::{audit_manifest, audit_res_files};
use asc_fixture::{make_apk, make_dex};
use std::io::Write;

fn audit_apk(target_sdk: i32, stored: bool) -> tempfile::NamedTempFile {
    let (manifest, arsc) = audit_manifest(target_sdk);
    let files = audit_res_files();
    let dex = make_dex();
    let mut entries: Vec<(&str, &[u8])> = vec![("AndroidManifest.xml", &manifest), ("resources.arsc", &arsc), ("classes.dex", &dex)];
    entries.extend(files.iter().map(|(p, b)| (*p, b.as_slice())));
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&make_apk(&entries, !stored)).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn summary_lists_the_attack_surface() {
    let apk = audit_apk(30, true);
    let s = Engine::new(apk.path()).manifest_summary().unwrap();
    assert_eq!((s.package.as_str(), s.min_sdk, s.target_sdk), ("com.demo", Some(21), Some(30)));
    assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    let lines = s.lines();
    let has = |want: &str| assert!(lines.iter().any(|l| l == want), "missing {want:?} in\n{}", lines.join("\n"));
    has("package com.demo versionCode=- versionName=- minSdk=21 targetSdk=30 sharedUserId=-");
    has("application class=com.demo.App debuggable=true allowBackup=false testOnly=false usesCleartextTraffic=- \
         cleartext=false(networkSecurityConfig) networkSecurityConfig=res/xml/network_security_config.xml permission=- \
         fullBackupContent=- dataExtractionRules=-");
    has("uses-permission android.permission.INTERNET");
    has("permission com.demo.SECRET protectionLevel=signature");
    // A reference whose value differs by SDK: the newest device's value wins, both are listed.
    has("activity com.demo.Main exported=true (explicit, @bool/exported_flag varies: default=false,v31=true)");
    // No exported attribute, an intent filter, targetSdk 30: implicitly exported.
    has("activity com.demo.Implicit exported=true (intent-filter)");
    has("service com.demo.Sync exported=false (default) permission=com.demo.SECRET");
    has("provider androidx.core.content.FileProvider exported=false (explicit) authorities=com.demo.files grantUriPermissions=true");
    has("provider-path com.demo.files root-path name=root path=");
    has("receiver com.demo.Boot exported=true (explicit)");
    has("deeplink com.demo.Main https://demo.com/open*");
    has("deeplink com.demo.Implicit demo://x/open*");
    has("nsc base-config cleartextTrafficPermitted=false trust-anchors=");
    let json = s.json();
    assert_eq!(json["components"][1]["exported_reason"], "intent-filter");
    assert_eq!(json["components"][3]["provider_paths"][0], "root-path name=root path=");
    assert_eq!(json["components"][0]["deep_links"][0], "https://demo.com/open*");
    assert_eq!(json["application"]["cleartext_source"], "networkSecurityConfig");
}

#[test]
fn targetsdk_31_requires_explicit_exported() {
    let apk = audit_apk(31, false);
    let s = Engine::new(apk.path()).manifest_summary().unwrap();
    let implicit = s.components.iter().find(|c| c.class == "com.demo.Implicit").unwrap();
    assert!(!implicit.exported);
    assert_eq!(implicit.exported_reason, "missing (install fails on targetSdk>=31)");
}

#[test]
fn resources_query_resolve_search_and_xml() {
    for stored in [true, false] {
        let apk = audit_apk(30, stored);
        let e = Engine::new(apk.path());
        let rows: Vec<String> = e.resource("bool/exported_flag").unwrap().iter().map(|r| r.line()).collect();
        assert_eq!(rows, ["0x7f020000 bool/exported_flag false", "0x7f020000 bool/exported_flag [v31] true"]);
        assert_eq!(e.resource("0x7f010000").unwrap()[0].value, "\"Demo\"");
        let (chain, row) = e.resolve_resource("@string/app_name", None).unwrap();
        assert_eq!((chain, row.value.as_str()), (vec!["@string/app_name".to_string()], "\"Demo\""));
        assert!(e.resource("string/nope").is_err());
        let (hits, total) = e.search_resources("res/xml", true, ResourceField::Value, 1).unwrap();
        assert_eq!((hits.len(), total), (1, 2));
        let (hits, _) = e.search_resources("^xml/", false, ResourceField::Name, 10).unwrap();
        assert_eq!(hits.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["xml/network_security_config", "xml/file_paths"]);
        let xml = e.manifest_xml_resolved().unwrap();
        assert!(xml.contains("android:exported=\"@bool/exported_flag\""), "{xml}");
        assert!(xml.contains("android:networkSecurityConfig=\"@xml/network_security_config\""), "{xml}");
        // The raw form keeps the ids.
        assert!(e.manifest_xml().unwrap().contains("android:exported=\"@7F020000\""));
        let mut n = 0;
        e.dump_resources(|_| n += 1).unwrap();
        assert_eq!(n, 5);
    }
}

#[test]
fn apk_without_resources_still_summarizes() {
    let (manifest, _) = audit_manifest(30);
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&make_apk(&[("AndroidManifest.xml", &manifest)], true)).unwrap();
    let e = Engine::new(f.path());
    assert!(e.resources().unwrap().is_none());
    let s = e.manifest_summary().unwrap();
    assert!(s.warnings.iter().any(|w| w.contains("no resources.arsc")), "{:?}", s.warnings);
    assert!(e.resource("string/app_name").is_err());
}
