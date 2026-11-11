use serde_json::json;

use crate::{AbilityKind, ApiVersion, HapError, ModuleJson, PackInfo, PageList, PkgContextInfo, RouterMap, SkillUri};

fn module(json: serde_json::Value) -> ModuleJson {
    ModuleJson::parse(json.to_string().as_bytes()).unwrap()
}

fn notes(m: &ModuleJson) -> Vec<String> {
    m.notes.iter().map(ToString::to_string).collect()
}

/// A manifest exercising every modelled section, in the packed spelling.
const REALISTIC: &str = r#"{
  "app": {
    "bundleName": "com.example.shop", "bundleType": "app", "vendor": "Example Inc", "versionCode": 10200, "versionName": "1.2.0",
    "debug": false, "minAPIVersion": 50001013, "targetAPIVersion": 50003015, "apiReleaseType": "Release",
    "compileSdkType": "HarmonyOS", "compileSdkVersion": "5.0.3.100", "buildMode": "release",
    "icon": "$media:logo", "iconId": 16777217, "label": "$string:app_name", "labelId": 16777216,
    "appEnvironments": [{ "name": "DFX_OPTIONS", "value": "oomdump:enable" }]
  },
  "module": {
    "name": "entry", "type": "entry", "packageName": "entry", "mainElement": "EntryAbility",
    "srcEntry": "./ets/entryability/Stage.ets", "deviceTypes": ["phone", "tablet"], "virtualMachine": "ark12.0.6.0",
    "compileMode": "esmodule", "installationFree": false, "deliveryWithInstall": true, "compressNativeLibs": true,
    "pages": "$profile:main_pages", "routerMap": "$profile:router_map", "description": "$string:module_desc", "descriptionId": 1,
    "metadata": [{ "name": "client_id", "value": "100000002" }],
    "dependencies": [{ "bundleName": "com.example.lib", "moduleName": "shared", "versionCode": 7 }],
    "querySchemes": ["examplepay", "examplechat"],
    "proxyData": [{ "uri": "datashareproxy://com.example.shop/cart", "requiredReadPermission": "com.example.shop.READ_CART",
                    "metadata": { "name": "dataProperties", "resource": "$profile:cart_config" } }],
    "requestPermissions": [
      { "name": "ohos.permission.INTERNET" },
      { "name": "ohos.permission.LOCATION", "reason": "$string:why_location", "reasonId": 5,
        "usedScene": { "abilities": ["EntryAbility"], "when": "inuse" } }
    ],
    "definePermissions": [{ "name": "com.example.shop.READ_CART", "grantMode": "system_grant", "availableLevel": "normal",
                            "provisionEnable": true, "distributedSceneEnable": false }],
    "testRunner": { "name": "OpenHarmonyTestRunner", "srcPath": "testrunner" },
    "atomicService": { "preloads": [{ "moduleName": "feature" }] },
    "abilities": [
      {
        "name": "EntryAbility", "srcEntry": "./ets/entryability/EntryAbility.ets", "exported": true, "launchType": "singleton",
        "label": "$string:EntryAbility_label", "labelId": 2, "icon": "$media:icon", "iconId": 3,
        "startWindowIcon": "$media:icon", "startWindowIconId": 3, "orientation": "follow_desktop", "backgroundModes": ["audioPlayback"],
        "skills": [
          { "entities": ["entity.system.home"], "actions": ["action.system.home"] },
          { "entities": ["entity.system.browsable"], "actions": ["ohos.want.action.viewData"], "domainVerify": true,
            "uris": [
              { "scheme": "shop" },
              { "scheme": "https", "host": "app.example.com", "port": "8443", "pathStartWith": "goods" },
              { "scheme": "https", "host": "app.example.com", "path": "/pay", "linkFeature": "Payment" },
              { "scheme": "qq", "host": "100000001", "pathRegex": "\\b(auth|share)\\b" },
              { "scheme": "file", "type": "image/*", "utd": "general.image", "maxFileSupported": 9 }
            ] }
        ],
        "metadata": [{ "name": "ohos.ability.shortcuts", "resource": "$profile:shortcuts_config", "resourceId": 9 }]
      },
      { "name": "PayAbility", "srcEntry": "./ets/pay/PayAbility.ets", "permissions": ["com.example.shop.PAY"],
        "skills": [{ "actions": ["com.example.shop.action.PAY"] }] }
    ],
    "extensionAbilities": [
      { "name": "CartData", "type": "dataShare", "srcEntry": "./ets/data/CartData.ets", "exported": true,
        "uri": "datashare://com.example.shop.cart", "readPermission": "com.example.shop.READ_CART" },
      { "name": "EntryFormAbility", "type": "form", "srcEntry": "./ets/card/EntryFormAbility.ets",
        "metadata": [{ "name": "ohos.extension.form", "resource": "$profile:form_config", "resourceId": 4 }] }
    ]
  }
}"#;

#[test]
fn summary_of_a_realistic_manifest() {
    let m = ModuleJson::parse(REALISTIC.as_bytes()).unwrap();
    let expected = r#"bundle com.example.shop bundleType=app versionCode=10200 versionName=1.2.0 vendor="Example Inc" debug=false minAPIVersion=50001013(13) targetAPIVersion=50003015(15) apiReleaseType=Release compileSdkType=HarmonyOS compileSdkVersion=5.0.3.100 buildMode=release
app-env name=DFX_OPTIONS value=oomdump:enable
module entry type=entry packageName=entry mainElement=EntryAbility srcEntry=./ets/entryability/Stage.ets deviceTypes=phone,tablet virtualMachine=ark12.0.6.0 compileMode=esmodule installationFree=false deliveryWithInstall=true process=- pages=$profile:main_pages routerMap=$profile:router_map compressNativeLibs=true
module-metadata name=client_id value=100000002
dependency bundleName=com.example.lib moduleName=shared versionCode=7
query-scheme examplepay
query-scheme examplechat
proxy-data uri=datashareproxy://com.example.shop/cart requiredReadPermission=com.example.shop.READ_CART requiredWritePermission=- metadataName=dataProperties metadataResource=$profile:cart_config
request-permission ohos.permission.INTERNET reason=- when=- abilities=-
request-permission ohos.permission.LOCATION reason=$string:why_location when=inuse abilities=EntryAbility
define-permission com.example.shop.READ_CART grantMode=system_grant availableLevel=normal provisionEnable=true distributedSceneEnable=false
test-runner name=OpenHarmonyTestRunner srcPath=testrunner
atomic-service preloads=feature
ability EntryAbility exported=true (explicit) permissions=- skills=2 srcEntry=./ets/entryability/EntryAbility.ets launchType=singleton backgroundModes=audioPlayback
skill EntryAbility skill=1 actions=action.system.home entities=entity.system.home uris=0 permissions=-
skill EntryAbility skill=2 actions=ohos.want.action.viewData entities=entity.system.browsable uris=5 permissions=- domainVerify=true
uri EntryAbility skill=2 scheme=shop
uri EntryAbility skill=2 scheme=https host=app.example.com port=8443 pathStartWith=goods
uri EntryAbility skill=2 scheme=https host=app.example.com path=/pay linkFeature=Payment
uri EntryAbility skill=2 scheme=qq host=100000001 pathRegex=\b(auth|share)\b
uri EntryAbility skill=2 scheme=file type=image/* utd=general.image maxFileSupported=9
deeplink EntryAbility shop://*
deeplink EntryAbility https://app.example.com:8443/goods*
deeplink EntryAbility https://app.example.com/pay
deeplink EntryAbility qq://100000001/regex:\b(auth|share)\b
deeplink EntryAbility file://*
metadata EntryAbility name=ohos.ability.shortcuts resource=$profile:shortcuts_config
ability PayAbility exported=false (default) permissions=com.example.shop.PAY skills=1 srcEntry=./ets/pay/PayAbility.ets
skill PayAbility skill=1 actions=com.example.shop.action.PAY entities=- uris=0 permissions=-
extension CartData type=dataShare exported=true (explicit) permissions=- skills=0 srcEntry=./ets/data/CartData.ets uri=datashare://com.example.shop.cart readPermission=com.example.shop.READ_CART writePermission=-
extension EntryFormAbility type=form exported=false (default) permissions=- skills=0 srcEntry=./ets/card/EntryFormAbility.ets
metadata EntryFormAbility name=ohos.extension.form resource=$profile:form_config
"#;
    assert_eq!(m.summary(), expected);
    assert!(m.notes.is_empty() && m.unmodelled.is_empty(), "{:?} {:?}", m.notes, m.unmodelled);
}

#[test]
fn app_fields() {
    let m = ModuleJson::parse(REALISTIC.as_bytes()).unwrap();
    assert_eq!(m.app.bundle_name.as_deref(), Some("com.example.shop"));
    assert_eq!(m.app.version_code, Some(10200));
    assert_eq!(m.app.debug, Some(false));
    assert_eq!(m.app.min_api_version.map(ApiVersion::level), Some(13));
    assert_eq!(m.app.target_api_version, Some(ApiVersion(50003015)));
    assert_eq!(m.app.environments[0].value.as_deref(), Some("oomdump:enable"));
    assert_eq!(m.app.label.as_deref(), Some("$string:app_name"));
}

#[test]
fn api_version_display() {
    assert_eq!(ApiVersion(9).to_string(), "9");
    assert_eq!(ApiVersion(60000020).to_string(), "60000020(20)");
}

#[test]
fn module_fields() {
    let m = ModuleJson::parse(REALISTIC.as_bytes()).unwrap().module;
    assert_eq!(m.kind.as_deref(), Some("entry"));
    assert_eq!(m.device_types, ["phone", "tablet"]);
    assert_eq!(m.delivery_with_install, Some(true));
    assert_eq!(m.router_map.as_deref(), Some("$profile:router_map"));
    assert_eq!(m.metadata[0].value.as_deref(), Some("100000002"));
    assert_eq!(m.dependencies[0].version_code, Some(7));
    assert_eq!(m.proxy_data[0].metadata.as_ref().unwrap().resource.as_deref(), Some("$profile:cart_config"));
    assert_eq!(m.query_schemes, ["examplepay", "examplechat"]);
    assert_eq!(m.test_runner.unwrap().src_path.as_deref(), Some("testrunner"));
    assert_eq!(m.atomic_service.unwrap().preloads, ["feature"]);
}

#[test]
fn permissions() {
    let m = ModuleJson::parse(REALISTIC.as_bytes()).unwrap().module;
    let location = &m.request_permissions[1];
    assert_eq!(location.name.as_deref(), Some("ohos.permission.LOCATION"));
    assert_eq!(location.used_when.as_deref(), Some("inuse"));
    assert_eq!(location.used_abilities, ["EntryAbility"]);
    assert_eq!(m.request_permissions[0].used_when, None);
    let defined = &m.define_permissions[0];
    assert_eq!(defined.grant_mode.as_deref(), Some("system_grant"));
    assert_eq!(defined.provision_enable, Some(true));
}

#[test]
fn abilities_and_extensions() {
    let m = ModuleJson::parse(REALISTIC.as_bytes()).unwrap();
    let names: Vec<_> = m.components().map(|a| (a.kind, a.name.as_deref().unwrap(), a.exported)).collect();
    assert_eq!(
        names,
        [
            (AbilityKind::Ability, "EntryAbility", Some(true)),
            (AbilityKind::Ability, "PayAbility", None),
            (AbilityKind::Extension, "CartData", Some(true)),
            (AbilityKind::Extension, "EntryFormAbility", None),
        ]
    );
    let pay = &m.module.abilities[1];
    assert!(!pay.is_exported());
    assert_eq!(pay.permissions, ["com.example.shop.PAY"]);
    let cart = &m.module.extension_abilities[0];
    assert_eq!(cart.extension_type.as_deref(), Some("dataShare"));
    assert_eq!(cart.uri.as_deref(), Some("datashare://com.example.shop.cart"));
    assert_eq!(cart.write_permission, None);
    // Unmodelled fields stay reachable on the entry itself.
    assert_eq!(m.module.abilities[0].raw["orientation"], "follow_desktop");
    assert_eq!(m.raw()["module"]["abilities"][0]["iconId"], 3);
}

#[test]
fn uri_patterns() {
    let uri = |v: serde_json::Value| -> Vec<String> {
        let m = module(json!({ "module": { "abilities": [{ "skills": [{ "uris": [v] }] }] } }));
        m.module.abilities[0].skills[0].uris[0].patterns()
    };
    assert_eq!(uri(json!({ "scheme": "a" })), ["a://*"]);
    assert_eq!(uri(json!({ "scheme": "a", "host": "h" })), ["a://h"]);
    assert_eq!(uri(json!({ "scheme": "a", "host": "h", "port": 80 })), ["a://h:80"]);
    assert_eq!(uri(json!({ "scheme": "a", "port": "80" })), ["a://*:80"]);
    assert_eq!(uri(json!({ "scheme": "a", "path": "p/q" })), ["a://*/p/q"]);
    assert_eq!(
        uri(json!({ "scheme": "a", "host": "h", "path": "/p", "pathStartWith": "/s", "pathRegex": ".*" })),
        ["a://h/p", "a://h/s*", "a://h/regex:.*"]
    );
    assert_eq!(uri(json!({ "host": "h", "type": "text/plain" })), [] as [&str; 0]);
    assert_eq!(SkillUri::default().patterns(), [] as [&str; 0]);
}

#[test]
fn deep_links_do_not_repeat() {
    let m = module(json!({ "module": { "abilities": [{ "name": "A", "skills": [
        { "uris": [{ "scheme": "x" }, { "scheme": "y" }] }, { "uris": [{ "scheme": "x" }] }
    ] }] } }));
    assert_eq!(m.module.abilities[0].deep_links(), ["x://*", "y://*"]);
}

#[test]
fn values_with_whitespace_are_quoted() {
    let m = module(json!({ "app": { "bundleName": "", "vendor": "a b" }, "module": { "abilities": [{ "name": "A\nB" }] } }));
    let lines = m.summary_lines();
    assert!(lines[0].starts_with(r#"bundle "" bundleType=- versionCode=- versionName=- vendor="a b" "#), "{}", lines[0]);
    assert!(lines[2].starts_with(r#"ability "A\nB" exported=false (default)"#), "{}", lines[2]);
    assert!(lines.iter().all(|l| !l.contains('\n')));
}

#[test]
fn empty_object_is_an_empty_manifest() {
    let m = ModuleJson::parse(b"{}").unwrap();
    assert!(m.notes.is_empty() && m.unmodelled.is_empty());
    assert_eq!(
        m.summary(),
        "bundle - bundleType=- versionCode=- versionName=- vendor=- debug=- minAPIVersion=- targetAPIVersion=- apiReleaseType=- compileSdkType=- compileSdkVersion=- buildMode=-\n\
         module - type=- packageName=- mainElement=- srcEntry=- deviceTypes=- virtualMachine=- compileMode=- installationFree=- deliveryWithInstall=- process=- pages=-\n"
    );
    assert_eq!(m.pretty(), "{}\n");
}

#[test]
fn wrong_types_are_noted_and_skipped() {
    let m = module(json!({
        "app": { "bundleName": 7, "versionCode": "12", "debug": "yes", "appEnvironments": {} },
        "module": {
            "name": "entry",
            "deviceTypes": ["phone", 3],
            "abilities": [
                "oops",
                { "name": "A", "exported": "true", "skills": [{ "actions": "view", "uris": [1, { "scheme": "s", "port": [] }] }], "permissions": null }
            ],
            "extensionAbilities": 5,
            "requestPermissions": [{ "name": "p", "usedScene": [] }],
            "testRunner": "x"
        }
    }));
    assert_eq!(
        notes(&m),
        [
            "app.bundleName: expected string, found number",
            "app.versionCode: expected integer, found string",
            "app.debug: expected boolean, found string",
            "app.appEnvironments: expected array, found object",
            "module.deviceTypes[1]: expected string, found number",
            "module.abilities[0]: expected object, found string",
            "module.abilities[1].exported: expected boolean, found string",
            "module.abilities[1].skills[0].actions: expected array, found string",
            "module.abilities[1].skills[0].uris[0]: expected object, found number",
            "module.abilities[1].skills[0].uris[1].port: expected string, number or boolean, found array",
            "module.extensionAbilities: expected array, found number",
            "module.requestPermissions[0].usedScene: expected object, found array",
            "module.testRunner: expected object, found string",
        ]
    );
    // Everything well-typed around the bad fields is kept.
    assert_eq!(m.module.name.as_deref(), Some("entry"));
    assert_eq!(m.module.device_types, ["phone"]);
    let a = &m.module.abilities[0];
    assert_eq!((a.name.as_deref(), a.exported), (Some("A"), None));
    assert_eq!(a.deep_links(), ["s://*"]);
    assert_eq!(m.module.request_permissions[0].name.as_deref(), Some("p"));
    let summary = m.summary();
    assert!(summary.contains("ability A exported=false (default)"));
    assert!(summary.ends_with("note module.testRunner: expected object, found string\n"));
}

#[test]
fn wrongly_typed_sections() {
    let m = module(json!({ "app": [], "module": "entry" }));
    assert_eq!(notes(&m), ["app: expected object, found array", "module: expected object, found string"]);
    assert_eq!(m.module.abilities.len(), 0);
}

#[test]
fn unknown_fields_are_listed_not_fatal() {
    let m = module(json!({
        "future": 1,
        "app": { "bundleName": "b", "asanEnabled": true, "labelId": 4, "label": "$string:l", "iconId": 1, "strayId": 2 },
        "module": { "abilities": [{ "name": "A", "novel": {}, "skills": [{ "uris": [{ "scheme": "s", "x": 1 }] }] }] }
    }));
    assert!(m.notes.is_empty());
    assert_eq!(
        m.unmodelled, // Inner objects report before the object that holds them.
        ["app.asanEnabled", "app.strayId", "module.abilities[0].skills[0].uris[0].x", "module.abilities[0].novel", "future"]
    );
    assert!(m.summary().contains("unmodelled app.asanEnabled\n"));
    assert_eq!(m.raw()["app"]["asanEnabled"], true);
}

#[test]
fn input_that_is_not_a_json_object() {
    assert!(matches!(ModuleJson::parse(b""), Err(HapError::Json(_))));
    assert!(matches!(ModuleJson::parse(b"   "), Err(HapError::Json(_))));
    assert!(matches!(ModuleJson::parse(b"{\"app\": {"), Err(HapError::Json(_))));
    assert!(matches!(ModuleJson::parse(b"\xff\xfe"), Err(HapError::Json(_))));
    assert!(matches!(ModuleJson::parse(b"{} trailing"), Err(HapError::Json(_))));
    for (text, found) in [("[]", "array"), ("null", "null"), ("3", "number"), ("\"s\"", "string"), ("true", "boolean")] {
        let err = ModuleJson::parse(text.as_bytes()).unwrap_err();
        assert!(matches!(err, HapError::NotAnObject { found: f } if f == found), "{text}: {err}");
        assert!(PackInfo::parse(text.as_bytes()).is_err() && PkgContextInfo::parse(text.as_bytes()).is_err());
    }
    assert_eq!(ModuleJson::parse(b"[]").unwrap_err().to_string(), "expected a JSON object at the root, found array");
}

#[test]
fn byte_order_mark_is_accepted() {
    let m = ModuleJson::parse(b"\xef\xbb\xbf{\"app\":{\"bundleName\":\"b\"}}").unwrap();
    assert_eq!(m.app.bundle_name.as_deref(), Some("b"));
}

#[test]
fn deep_nesting_is_an_error_not_a_stack_overflow() {
    let depth = 200_000;
    let deep = format!("{{\"app\":{}{}}}", "[".repeat(depth), "]".repeat(depth));
    assert!(matches!(ModuleJson::parse(deep.as_bytes()), Err(HapError::Json(_))));
    let deep = "{\"a\":".repeat(depth);
    assert!(matches!(PkgContextInfo::parse(deep.as_bytes()), Err(HapError::Json(_))));
}

#[test]
fn large_input() {
    let abilities: Vec<_> = (0..20_000)
        .map(|i| json!({ "name": format!("A{i}"), "exported": i % 2 == 0, "skills": [{ "uris": [{ "scheme": format!("s{i}") }] }] }))
        .collect();
    let m = module(json!({ "module": { "abilities": abilities } }));
    assert_eq!(m.module.abilities.len(), 20_000);
    assert_eq!(m.summary_lines().iter().filter(|l| l.starts_with("deeplink ")).count(), 20_000);
}

#[test]
fn fixture_manifest() {
    let m = ModuleJson::parse(asc_fixture::hap::SAMPLE_MODULE_JSON.as_bytes()).unwrap();
    assert!(m.notes.is_empty() && m.unmodelled.is_empty(), "{:?} {:?}", m.notes, m.unmodelled);
    assert_eq!(m.app.bundle_name.as_deref(), Some("com.example.sample"));
    let entry = &m.module.abilities[0];
    assert!(entry.is_exported());
    assert_eq!(entry.deep_links(), ["sample://open"]);
    assert_eq!(m.module.request_permissions.len(), 1);
    let summary = m.summary();
    assert!(
        summary.contains(
            "ability EntryAbility exported=true (explicit) permissions=- skills=1 srcEntry=./ets/entryability/EntryAbility.ets\n"
        )
    );
    assert!(summary.contains("deeplink EntryAbility sample://open\n"));
    assert!(summary.contains("request-permission ohos.permission.INTERNET reason=- when=- abilities=-\n"));

    let pack = PackInfo::parse(asc_fixture::hap::SAMPLE_PACK_INFO.as_bytes()).unwrap();
    assert!(pack.notes.is_empty() && pack.unmodelled.is_empty(), "{:?} {:?}", pack.notes, pack.unmodelled);
    assert_eq!(pack.app.bundle_name, m.app.bundle_name);
}

const PACK_INFO: &str = r#"{
  "summary": {
    "app": { "bundleName": "com.example.shop", "bundleType": "app", "version": { "code": 10200, "name": "1.2.0" } },
    "modules": [{
      "mainAbility": "EntryAbility", "deviceType": ["phone", "tablet"],
      "abilities": [{ "name": "EntryAbility", "label": "$string:EntryAbility_label" }],
      "extensionAbilities": [{ "name": "EntryFormAbility", "forms": [{
        "name": "Card", "type": "JS", "updateEnabled": true, "updateDuration": 1, "supportDimensions": ["2*2", "2*4"], "defaultDimension": "2*2" }] }],
      "distro": { "moduleType": "entry", "installationFree": false, "deliveryWithInstall": true, "moduleName": "entry" },
      "apiVersion": { "compatible": 13, "releaseType": "Release", "target": 15 }
    }]
  },
  "packages": [{ "deviceType": ["phone", "tablet"], "moduleType": "entry", "deliveryWithInstall": true, "name": "entry-default" }]
}"#;

#[test]
fn pack_info() {
    let p = PackInfo::parse(PACK_INFO.as_bytes()).unwrap();
    assert!(p.notes.is_empty() && p.unmodelled.is_empty(), "{:?} {:?}", p.notes, p.unmodelled);
    assert_eq!(p.app.version_code, Some(10200));
    assert_eq!(p.modules[0].api_compatible, Some(13));
    assert_eq!(p.modules[0].extension_abilities[0].forms[0].support_dimensions, ["2*2", "2*4"]);
    assert_eq!(p.packages[0].name.as_deref(), Some("entry-default"));
    assert_eq!(
        p.summary(),
        "pack-app com.example.shop bundleType=app versionCode=10200 versionName=1.2.0\n\
         pack-module entry type=entry mainAbility=EntryAbility deviceTypes=phone,tablet installationFree=false deliveryWithInstall=true apiCompatible=13 apiTarget=15 apiReleaseType=Release\n\
         pack-ability entry EntryAbility label=$string:EntryAbility_label\n\
         pack-extension entry EntryFormAbility forms=1\n\
         pack-form entry EntryFormAbility Card type=JS updateEnabled=true updateDuration=1 defaultDimension=2*2 supportDimensions=2*2,2*4\n\
         pack-package entry-default moduleType=entry deviceTypes=phone,tablet deliveryWithInstall=true\n"
    );
}

#[test]
fn pack_info_tolerance() {
    let p =
        PackInfo::parse(br#"{"summary": {"app": {"version": 3}, "modules": [1, {"distro": [], "extra": 0}]}, "packages": {}}"#).unwrap();
    let notes: Vec<_> = p.notes.iter().map(ToString::to_string).collect();
    assert_eq!(
        notes,
        [
            "summary.app.version: expected object, found number",
            "summary.modules[0]: expected object, found number",
            "summary.modules[1].distro: expected object, found array",
            "packages: expected array, found object",
        ]
    );
    assert_eq!(p.unmodelled, ["summary.modules[1].extra"]);
    assert_eq!(p.modules.len(), 1);
    assert_eq!(PackInfo::parse(b"{}").unwrap().summary(), "pack-app - bundleType=- versionCode=- versionName=-\n");
}

const PKG_CONTEXT: &str = r#"{
  "entry": { "isSO": false, "moduleName": "", "bundleName": "", "dependencyAlias": "", "packageName": "entry", "entryPath": "src/main/", "version": "" },
  "@ohos/crypto-js": { "isSO": false, "moduleName": "", "bundleName": "", "dependencyAlias": "", "packageName": "@ohos/crypto-js", "entryPath": "index.ts", "version": "2.0.0" },
  "@ohos": { "isSO": false, "packageName": "@ohos", "entryPath": "", "version": "0.1" },
  "pako": { "isSO": false, "packageName": "pako", "entryPath": "dist/pako.esm.mjs", "version": "2.1.0" },
  "libcrypto.so": { "isSO": true, "moduleName": "", "bundleName": "", "dependencyAlias": "", "packageName": "libcrypto.so", "entryPath": "", "version": "" }
}"#;

#[test]
fn pkg_context_table() {
    let t = PkgContextInfo::parse(PKG_CONTEXT.as_bytes()).unwrap();
    assert!(t.notes.is_empty() && t.unmodelled.is_empty(), "{:?} {:?}", t.notes, t.unmodelled);
    let names: Vec<_> = t.packages().iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["@ohos", "@ohos/crypto-js", "entry", "libcrypto.so", "pako"]);
    let crypto = t.get("@ohos/crypto-js").unwrap();
    assert_eq!((crypto.version.as_str(), crypto.entry_path.as_str(), crypto.is_so), ("2.0.0", "index.ts", false));
    assert!(t.get("libcrypto.so").unwrap().is_so);
    assert!(t.get("@ohos/crypto").is_none());
    assert_eq!(
        t.summary(),
        "package @ohos version=0.1 entryPath=- isSO=false bundleName=- moduleName=- dependencyAlias=-\n\
         package @ohos/crypto-js version=2.0.0 entryPath=index.ts isSO=false bundleName=- moduleName=- dependencyAlias=-\n\
         package entry version=- entryPath=src/main/ isSO=false bundleName=- moduleName=- dependencyAlias=-\n\
         package libcrypto.so version=- entryPath=- isSO=true bundleName=- moduleName=- dependencyAlias=-\n\
         package pako version=2.1.0 entryPath=dist/pako.esm.mjs isSO=false bundleName=- moduleName=- dependencyAlias=-\n"
    );
}

#[test]
fn pkg_context_entry_records() {
    let t = PkgContextInfo::parse(PKG_CONTEXT.as_bytes()).unwrap();
    let entry = |name: &str| t.get(name).unwrap().entry_record_name();
    assert_eq!(entry("@ohos/crypto-js").as_deref(), Some("&@ohos/crypto-js/index&2.0.0"));
    assert_eq!(entry("pako").as_deref(), Some("&pako/dist/pako.esm&2.1.0"));
    assert_eq!(entry("entry"), None);
    assert_eq!(entry("libcrypto.so"), None);
    assert_eq!(entry("@ohos"), None);
}

#[test]
fn pkg_context_locates_records() {
    let t = PkgContextInfo::parse(PKG_CONTEXT.as_bytes()).unwrap();
    let owner = t.locate("&@ohos/crypto-js/src/main/js/aes&2.0.0").unwrap();
    assert_eq!((owner.package.name.as_str(), owner.bundle, owner.path, owner.version), ("@ohos/crypto-js", "", "src/main/js/aes", "2.0.0"));
    // The longest package name wins over its prefix `@ohos`.
    assert_eq!(t.locate("&@ohos/other/x&1").unwrap().package.name, "@ohos");
    let owner = t.locate("com.other&entry/src/main/ets/pages/Index&").unwrap();
    assert_eq!(
        (owner.package.name.as_str(), owner.bundle, owner.path, owner.version),
        ("entry", "com.other", "src/main/ets/pages/Index", "")
    );
    assert_eq!(t.locate("&pako&2.1.0").unwrap().path, "");
    assert!(t.locate("&entryability/x&").is_none());
    assert!(t.locate("&unknown/x&").is_none());
    assert!(t.locate("com.x.y/entry/ets/pages/Index").is_none());
    assert!(t.locate("&only-one-ampersand").is_none());
    assert!(t.locate("").is_none());
}

#[test]
fn pkg_context_tolerance() {
    let t = PkgContextInfo::parse(br#"{"a": 1, "b": {"isSO": "no", "version": 2, "new": true}, "c": {}}"#).unwrap();
    let notes: Vec<_> = t.notes.iter().map(ToString::to_string).collect();
    assert_eq!(notes, ["a: expected object, found number", "b.isSO: expected boolean, found string"]);
    assert_eq!(t.unmodelled, ["b.new"]);
    assert_eq!(t.get("b").unwrap().version, "2");
    assert_eq!(t.get("c").unwrap().package_name, "");
    assert!(t.summary().contains("package c version=- entryPath=- isSO=false bundleName=- moduleName=- dependencyAlias=- packageName=-\n"));
    assert!(PkgContextInfo::parse(b"{}").unwrap().packages().is_empty());
}

#[test]
fn record_names() {
    let m = module(json!({ "app": { "bundleName": "com.x.y" }, "module": { "name": "entry", "packageName": "entry" } }));
    let without = m.record_names("./ets/entryability/EntryAbility.ets", None);
    assert_eq!(without.normalized.as_deref(), Some("&entry/src/main/ets/entryability/EntryAbility&"));
    assert_eq!(without.bundled.as_deref(), Some("com.x.y/entry/ets/entryability/EntryAbility"));
    assert_eq!(without.candidates(), ["com.x.y/entry/ets/entryability/EntryAbility", "&entry/src/main/ets/entryability/EntryAbility&"]);

    let table = PkgContextInfo::parse(PKG_CONTEXT.as_bytes()).unwrap();
    let with = m.record_names("./ets/entryability/EntryAbility.ets", Some(&table));
    assert_eq!(with.candidates(), ["&entry/src/main/ets/entryability/EntryAbility&", "com.x.y/entry/ets/entryability/EntryAbility"]);

    // The table's source root and version are used, whatever they are.
    let table = PkgContextInfo::parse(br#"{"entry": {"entryPath": "lib/", "version": "1.2.3"}}"#).unwrap();
    assert_eq!(m.record_names("ets/a/B.ts", Some(&table)).normalized.as_deref(), Some("&entry/lib/ets/a/B&1.2.3"));
    // A shared package lists its entry file there, or nothing: its sources are where they always are.
    for entry_path in ["", "Index.ets"] {
        let table =
            PkgContextInfo::parse(format!(r#"{{"entry": {{"entryPath": "{entry_path}", "version": "2.0.0"}}}}"#).as_bytes()).unwrap();
        assert_eq!(m.record_names("ets/a/B.ts", Some(&table)).normalized.as_deref(), Some("&entry/src/main/ets/a/B&2.0.0"));
    }

    for (source, path) in [
        ("./ets/a/B.ts", "ets/a/B"),
        ("ets/a/B.js", "ets/a/B"),
        ("/ets/a/B", "ets/a/B"),
        ("./ets/a/B.d.ets", "ets/a/B.d"),
        ("./ets/a.b/C.txt", "ets/a.b/C.txt"),
    ] {
        assert_eq!(m.record_names(source, None).bundled.unwrap(), format!("com.x.y/entry/{path}"), "{source}");
    }
}

#[test]
fn record_names_with_missing_manifest_fields() {
    let m = module(json!({ "module": { "name": "feature" } }));
    let names = m.record_names("./ets/A.ets", None);
    assert_eq!((names.normalized.as_deref(), names.bundled.as_deref()), (Some("&feature/src/main/ets/A&"), None));
    assert_eq!(names.candidates(), ["&feature/src/main/ets/A&"]);
    assert!(module(json!({})).record_names("./ets/A.ets", None).candidates().is_empty());
}

#[test]
fn fields_of_newer_packages_are_modelled() {
    let m = module(json!({
        "app": {
            "bundleName": "com.x.y", "minMinorAPIVersion": 0, "minPatchAPIVersion": 0, "GWPAsanEnabled": true,
            "multiAppMode": { "multiAppModeType": "appClone", "maxCount": 2 }
        },
        "module": { "abilities": [{
            "name": "Side", "removeMissionAfterTerminate": true, "startWindow": "$profile:start_window", "startWindowId": 7
        }] }
    }));
    assert!(m.unmodelled.is_empty() && m.notes.is_empty(), "{:?} {:?}", m.unmodelled, m.notes);
    let lines = m.summary_lines();
    assert!(lines[0].ends_with(" buildMode=- multiAppMode=appClone multiAppMaxCount=2 GWPAsanEnabled=true"), "{}", lines[0]);
    assert!(lines[2].ends_with(" srcEntry=- removeMissionAfterTerminate=true"), "{}", lines[2]);
    assert_eq!((m.app.min_minor_api_version, m.app.min_patch_api_version), (Some(0), Some(0)));

    let pack = PackInfo::parse(
        br#"{"summary": {"modules": [{"distro": {"moduleName": "entry"}, "extensionAbilities": [
            {"name": "Form", "forms": [{"name": "Card", "scheduledUpdateTime": "10:30", "updateEnabled": true}]}]}]}}"#,
    )
    .unwrap();
    assert!(pack.unmodelled.is_empty(), "{:?}", pack.unmodelled);
    assert!(pack.summary().contains("pack-form entry Form Card type=- updateEnabled=true updateDuration=- scheduledUpdateTime=10:30 "));
}

#[test]
fn page_lists_and_route_tables() {
    let pages = PageList::parse(br#"{"src": ["pages/Index", "pages/sub/Detail", 3], "window": {"designWidth": 720}}"#).unwrap();
    assert_eq!(pages.pages, ["pages/Index", "pages/sub/Detail"]);
    assert_eq!(pages.notes.len(), 1);
    assert_eq!(PageList::src_entry("pages/Index"), "./ets/pages/Index");
    assert!(PageList::parse(b"{}").unwrap().pages.is_empty());
    assert!(PageList::parse(b"[]").is_err());

    let table = RouterMap::parse(
        br#"{"routerMap": [
            {"name": "detail", "pageSourceFile": "src/main/ets/pages/Detail.ets", "buildFunction": "DetailBuilder",
             "ohmurl": "@normalized:N&&&entry/src/main/ets/pages/Detail&", "data": {"k": "v"}, "customData": [1]},
            {"name": "lib/pay", "pageSourceFile": "src/main/ets/Pay.ts", "buildFunction": "PayBuilder", "packageName": "@lib/pay",
             "ohmurl": "@normalized:N&shared&com.other&@lib/pay/src/main/ets/Pay&1.2.0"},
            {"name": "old", "pageSourceFile": "./src/main/ets/pages/Old.ets", "buildFunction": "OldBuilder"},
            {"name": "native", "ohmurl": "@normalized:Y&&&libpay.so&"},
            7
        ]}"#,
    )
    .unwrap();
    assert_eq!(table.routes.len(), 4);
    assert_eq!(table.notes.len(), 1);
    let records: Vec<Option<&str>> = table.routes.iter().map(|route| route.ohmurl_record()).collect();
    assert_eq!(records, [Some("&entry/src/main/ets/pages/Detail&"), Some("com.other&@lib/pay/src/main/ets/Pay&1.2.0"), None, None]);
    assert_eq!(table.routes[0].ohmurl_module(), Some(""));
    assert_eq!(table.routes[1].ohmurl_module(), Some("shared"));
    assert_eq!(table.routes[1].record_path(Some("entry")).as_deref(), Some("@lib/pay/src/main/ets/Pay"));
    assert_eq!(table.routes[2].record_path(Some("entry")).as_deref(), Some("entry/src/main/ets/pages/Old"));
    assert_eq!(table.routes[3].record_path(Some("entry")), None);

    let m = module(json!({ "app": { "bundleName": "com.x.y" }, "module": { "name": "entry", "packageName": "entry" } }));
    let packages =
        PkgContextInfo::parse(br#"{"entry": {"entryPath": "src/main/", "version": ""}, "@lib/pay": {"version": "1.2.0"}}"#).unwrap();
    let names = |index: usize, table_given: bool| m.route_record_names(&table.routes[index], table_given.then_some(&packages));
    // The ohmurl is the record; a page of the module itself may also be spelled by bundle and module.
    assert_eq!(names(0, false).candidates(), ["&entry/src/main/ets/pages/Detail&", "com.x.y/entry/ets/pages/Detail"]);
    assert_eq!(names(1, true).candidates(), ["com.other&@lib/pay/src/main/ets/Pay&1.2.0"]);
    // Without one, the name comes from the source file and the package table.
    assert_eq!(names(2, false).candidates(), ["com.x.y/entry/ets/pages/Old", "&entry/src/main/ets/pages/Old&"]);
    assert_eq!(names(2, true).candidates(), ["&entry/src/main/ets/pages/Old&", "com.x.y/entry/ets/pages/Old"]);
    let mut by_source = table.routes[1].clone();
    by_source.ohmurl = None;
    assert_eq!(m.route_record_names(&by_source, Some(&packages)).candidates(), ["&@lib/pay/src/main/ets/Pay&1.2.0"]);
    assert!(names(3, true).candidates().is_empty());
}
