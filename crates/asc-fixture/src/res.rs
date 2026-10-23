//! Hand-built binary XML documents and `resources.arsc` tables, enough for
//! manifest-summary and resource tests: one package, UTF-16 pools, plain
//! u32 entry tables, and a default plus `-vNN` configurations.

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// A typed attribute or resource value.
#[derive(Debug, Clone, Copy)]
pub enum Val<'a> {
    Str(&'a str),
    Bool(bool),
    Int(i32),
    /// `@0x7f...` reference.
    Ref(u32),
}

/// One element of a document to encode.
#[derive(Debug, Clone)]
pub struct El<'a> {
    pub name: &'a str,
    pub attrs: Vec<Attr<'a>>,
    pub children: Vec<El<'a>>,
}

/// An attribute: `android:` ones carry their framework id (as aapt writes them).
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    pub name: &'a str,
    pub res_id: Option<u32>,
    pub val: Val<'a>,
}

/// Framework ids of the `android:` attributes the fixtures use.
pub fn android_attr_id(name: &str) -> u32 {
    match name {
        "name" => 0x0101_0003,
        "permission" => 0x0101_0006,
        "readPermission" => 0x0101_0007,
        "writePermission" => 0x0101_0008,
        "debuggable" => 0x0101_000f,
        "exported" => 0x0101_0010,
        "host" => 0x0101_0028,
        "port" => 0x0101_0029,
        "path" => 0x0101_002a,
        "pathPrefix" => 0x0101_002b,
        "scheme" => 0x0101_0027,
        "protectionLevel" => 0x0101_0009,
        "authorities" => 0x0101_0018,
        "grantUriPermissions" => 0x0101_001b,
        "resource" => 0x0101_0025,
        "value" => 0x0101_0024,
        "minSdkVersion" => 0x0101_020c,
        "targetSdkVersion" => 0x0101_0270,
        "allowBackup" => 0x0101_0280,
        "usesCleartextTraffic" => 0x0101_04ec,
        "networkSecurityConfig" => 0x0101_0527,
        other => panic!("fixture has no id for android:{other}"),
    }
}

impl<'a> El<'a> {
    pub fn new(name: &'a str) -> El<'a> {
        El { name, attrs: Vec::new(), children: Vec::new() }
    }

    /// Add `android:name=val`.
    pub fn android(mut self, name: &'a str, val: Val<'a>) -> El<'a> {
        self.attrs.push(Attr { name, res_id: Some(android_attr_id(name)), val });
        self
    }

    /// Add an attribute without a namespace.
    pub fn plain(mut self, name: &'a str, val: Val<'a>) -> El<'a> {
        self.attrs.push(Attr { name, res_id: None, val });
        self
    }

    pub fn child(mut self, c: El<'a>) -> El<'a> {
        self.children.push(c);
        self
    }
}

fn chunk(kind: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(&((8 + header.len()) as u16).to_le_bytes());
    v.extend_from_slice(&((8 + header.len() + body.len()) as u32).to_le_bytes());
    v.extend_from_slice(header);
    v.extend_from_slice(body);
    v
}

/// A UTF-16 string pool chunk.
fn pool(strings: &[String]) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut data = Vec::new();
    for s in strings {
        offsets.extend_from_slice(&(data.len() as u32).to_le_bytes());
        let units: Vec<u16> = s.encode_utf16().collect();
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        units.iter().for_each(|u| data.extend_from_slice(&u.to_le_bytes()));
        data.extend_from_slice(&[0, 0]);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let mut header = Vec::new();
    header.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&((28 + offsets.len()) as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    chunk(0x0001, &header, &[offsets, data].concat())
}

struct Strings(Vec<String>);

impl Strings {
    fn idx(&mut self, s: &str) -> u32 {
        match self.0.iter().position(|x| x == s) {
            Some(i) => i as u32,
            None => {
                self.0.push(s.to_string());
                (self.0.len() - 1) as u32
            }
        }
    }
}

const NONE: u32 = 0xffff_ffff;

fn typed(val: Val, strings: &mut Strings) -> (u32, u8, u32) {
    match val {
        Val::Str(s) => {
            let i = strings.idx(s);
            (i, 0x03, i)
        }
        Val::Bool(b) => (NONE, 0x12, if b { 0xffff_ffff } else { 0 }),
        Val::Int(i) => (NONE, 0x10, i as u32),
        Val::Ref(id) => (NONE, 0x01, id),
    }
}

/// Encode `root` as a binary XML document (the `android` namespace declared
/// on the root, as aapt does).
pub fn axml(root: &El) -> Vec<u8> {
    // Names with a resource id come first: their pool index is their map index.
    let mut ids = Vec::new();
    let mut strings = Strings(Vec::new());
    fn collect<'a>(el: &El<'a>, out: &mut Vec<(&'a str, u32)>) {
        for a in &el.attrs {
            if let Some(id) = a.res_id {
                if !out.iter().any(|(n, _)| *n == a.name) {
                    out.push((a.name, id));
                }
            }
        }
        el.children.iter().for_each(|c| collect(c, out));
    }
    collect(root, &mut ids);
    for (name, _) in &ids {
        strings.idx(name);
    }
    let ns_prefix = strings.idx("android");
    let ns_uri = strings.idx(ANDROID_NS);
    let mut body = Vec::new();
    fn node(kind: u16, ext: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&NONE.to_le_bytes());
        chunk(kind, &header, ext)
    }
    let ns = [ns_prefix.to_le_bytes(), ns_uri.to_le_bytes()].concat();
    body.extend(node(0x0100, &ns));
    fn element(el: &El, strings: &mut Strings, ns_uri: u32, out: &mut Vec<u8>) {
        let name = strings.idx(el.name);
        let mut attrs = Vec::new();
        for a in &el.attrs {
            let ans = if a.res_id.is_some() { ns_uri } else { NONE };
            let aname = strings.idx(a.name);
            let (raw, kind, data) = typed(a.val, strings);
            attrs.extend_from_slice(&ans.to_le_bytes());
            attrs.extend_from_slice(&aname.to_le_bytes());
            attrs.extend_from_slice(&raw.to_le_bytes());
            attrs.extend_from_slice(&8u16.to_le_bytes());
            attrs.push(0);
            attrs.push(kind);
            attrs.extend_from_slice(&data.to_le_bytes());
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(&NONE.to_le_bytes());
        ext.extend_from_slice(&name.to_le_bytes());
        ext.extend_from_slice(&20u16.to_le_bytes());
        ext.extend_from_slice(&20u16.to_le_bytes());
        ext.extend_from_slice(&(el.attrs.len() as u16).to_le_bytes());
        ext.extend_from_slice(&[0u8; 6]);
        ext.extend_from_slice(&attrs);
        out.extend(node(0x0102, &ext));
        for c in &el.children {
            element(c, strings, ns_uri, out);
        }
        out.extend(node(0x0103, &[NONE.to_le_bytes(), name.to_le_bytes()].concat()));
    }
    element(root, &mut strings, ns_uri, &mut body);
    body.extend(node(0x0101, &ns));
    let map: Vec<u8> = ids.iter().flat_map(|(_, id)| id.to_le_bytes()).collect();
    let doc = [pool(&strings.0), chunk(0x0180, &[], &map), body].concat();
    chunk(0x0003, &[], &doc)
}

/// One resource of a fixture table: `type/name` with values per SDK
/// qualifier (0 = the default configuration).
#[derive(Debug, Clone)]
pub struct Res<'a> {
    pub type_name: &'a str,
    pub name: &'a str,
    pub values: Vec<(u16, Val<'a>)>,
}

impl<'a> Res<'a> {
    pub fn new(type_name: &'a str, name: &'a str, val: Val<'a>) -> Res<'a> {
        Res { type_name, name, values: vec![(0, val)] }
    }

    /// Also define the value for `-v{sdk}`.
    pub fn v(mut self, sdk: u16, val: Val<'a>) -> Res<'a> {
        self.values.push((sdk, val));
        self
    }
}

/// Resource ids [`arsc`] assigns: types numbered from 1 in first-use order,
/// entries from 0 in order within their type.
pub fn res_ids(resources: &[Res]) -> Vec<u32> {
    let mut types: Vec<&str> = Vec::new();
    let mut counts: Vec<u32> = Vec::new();
    resources
        .iter()
        .map(|r| {
            let t = match types.iter().position(|t| *t == r.type_name) {
                Some(t) => t,
                None => {
                    types.push(r.type_name);
                    counts.push(0);
                    types.len() - 1
                }
            };
            counts[t] += 1;
            0x7f00_0000 | ((t as u32 + 1) << 16) | (counts[t] - 1)
        })
        .collect()
}

/// Encode a one-package (`0x7f`, `package`) resource table.
pub fn arsc(package: &str, resources: &[Res]) -> Vec<u8> {
    let mut global = Strings(Vec::new());
    let mut type_names: Vec<String> = Vec::new();
    let mut keys = Strings(Vec::new());
    for r in resources {
        if !type_names.iter().any(|t| t == r.type_name) {
            type_names.push(r.type_name.to_string());
        }
        keys.idx(r.name);
    }
    let mut children = Vec::new();
    for (t, tname) in type_names.iter().enumerate() {
        let tid = t as u8 + 1;
        let members: Vec<(usize, &Res)> = resources.iter().enumerate().filter(|(_, r)| r.type_name == tname).collect();
        let count = members.len() as u32;
        let mut spec_header = vec![tid, 0, 0, 0];
        spec_header.extend_from_slice(&count.to_le_bytes());
        children.push(chunk(0x0202, &spec_header, &vec![0u8; count as usize * 4]));
        let mut sdks: Vec<u16> = members.iter().flat_map(|(_, r)| r.values.iter().map(|v| v.0)).collect();
        sdks.sort();
        sdks.dedup();
        for sdk in sdks {
            let mut offsets = Vec::new();
            let mut entries = Vec::new();
            for (_, r) in &members {
                match r.values.iter().find(|v| v.0 == sdk) {
                    Some(&(_, val)) => {
                        offsets.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                        let (_, kind, data) = typed(val, &mut global);
                        entries.extend_from_slice(&8u16.to_le_bytes());
                        entries.extend_from_slice(&0u16.to_le_bytes());
                        entries.extend_from_slice(&keys.idx(r.name).to_le_bytes());
                        entries.extend_from_slice(&8u16.to_le_bytes());
                        entries.push(0);
                        entries.push(kind);
                        entries.extend_from_slice(&data.to_le_bytes());
                    }
                    None => offsets.extend_from_slice(&0xffff_ffffu32.to_le_bytes()),
                }
            }
            let mut config = [0u8; 64];
            config[0..4].copy_from_slice(&64u32.to_le_bytes());
            config[24..26].copy_from_slice(&sdk.to_le_bytes());
            let mut header = vec![tid, 0, 0, 0];
            header.extend_from_slice(&count.to_le_bytes());
            header.extend_from_slice(&((8 + 12 + 64 + offsets.len()) as u32).to_le_bytes());
            header.extend_from_slice(&config);
            children.push(chunk(0x0201, &header, &[offsets, entries].concat()));
        }
    }
    let type_pool = pool(&type_names);
    let key_pool = pool(&keys.0);
    let mut header = Vec::new();
    header.extend_from_slice(&0x7fu32.to_le_bytes());
    let mut name: Vec<u8> = package.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    name.resize(256, 0);
    header.extend_from_slice(&name);
    header.extend_from_slice(&288u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&((288 + type_pool.len()) as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    let pkg = chunk(0x0200, &header, &[vec![type_pool, key_pool], children].concat().concat());
    chunk(0x0002, &1u32.to_le_bytes(), &[pool(&global.0), pkg].concat())
}

/// The audit fixture: a manifest exercising every manifest-summary rule and
/// its resource table. Returns `(AndroidManifest.xml, resources.arsc)`.
///
/// Resources: `string/app_name` = "Demo", `bool/exported_flag` = false
/// (true in `-v31`), `xml/network_security_config` and `xml/file_paths`
/// pointing at the two XML files of [`audit_res_files`].
pub fn audit_manifest(target_sdk: i32) -> (Vec<u8>, Vec<u8>) {
    let res = audit_resources();
    let ids = res_ids(&res);
    let (app_name, flag, nsc, paths) = (ids[0], ids[1], ids[2], ids[3]);
    let view = |scheme: &'static str, host: &'static str| {
        El::new("intent-filter")
            .child(El::new("action").android("name", Val::Str("android.intent.action.VIEW")))
            .child(El::new("category").android("name", Val::Str("android.intent.category.BROWSABLE")))
            .child(
                El::new("data")
                    .android("scheme", Val::Str(scheme))
                    .android("host", Val::Str(host))
                    .android("pathPrefix", Val::Str("/open")),
            )
    };
    let root = El::new("manifest")
        .plain("package", Val::Str("com.demo"))
        .child(El::new("uses-sdk").android("minSdkVersion", Val::Int(21)).android("targetSdkVersion", Val::Int(target_sdk)))
        .child(El::new("uses-permission").android("name", Val::Str("android.permission.INTERNET")))
        .child(El::new("permission").android("name", Val::Str("com.demo.SECRET")).android("protectionLevel", Val::Int(2)))
        .child(
            El::new("application")
                .android("name", Val::Str(".App"))
                .android("debuggable", Val::Bool(true))
                .android("networkSecurityConfig", Val::Ref(nsc))
                .android("allowBackup", Val::Bool(false))
                .child(
                    El::new("activity")
                        .android("name", Val::Str(".Main"))
                        .android("exported", Val::Ref(flag))
                        .child(view("https", "demo.com")),
                )
                .child(El::new("activity").android("name", Val::Str("com.demo.Implicit")).child(view("demo", "x")))
                .child(El::new("service").android("name", Val::Str(".Sync")).android("permission", Val::Str("com.demo.SECRET")))
                .child(
                    El::new("provider")
                        .android("name", Val::Str("androidx.core.content.FileProvider"))
                        .android("authorities", Val::Str("com.demo.files"))
                        .android("exported", Val::Bool(false))
                        .android("grantUriPermissions", Val::Bool(true))
                        .child(
                            El::new("meta-data")
                                .android("name", Val::Str("android.support.FILE_PROVIDER_PATHS"))
                                .android("resource", Val::Ref(paths)),
                        ),
                )
                .child(El::new("receiver").android("name", Val::Str(".Boot")).android("exported", Val::Bool(true)))
                .child(El::new("meta-data").android("name", Val::Str("label")).android("value", Val::Ref(app_name))),
        );
    (axml(&root), arsc("com.demo", &res))
}

fn audit_resources() -> Vec<Res<'static>> {
    vec![
        Res::new("string", "app_name", Val::Str("Demo")),
        Res::new("bool", "exported_flag", Val::Bool(false)).v(31, Val::Bool(true)),
        Res::new("xml", "network_security_config", Val::Str("res/xml/network_security_config.xml")),
        Res::new("xml", "file_paths", Val::Str("res/xml/file_paths.xml")),
    ]
}

/// `(path, bytes)` of the XML files the audit table points at.
pub fn audit_res_files() -> Vec<(&'static str, Vec<u8>)> {
    let nsc = El::new("network-security-config").child(El::new("base-config").plain("cleartextTrafficPermitted", Val::Bool(false))).child(
        El::new("domain-config")
            .plain("cleartextTrafficPermitted", Val::Bool(true))
            .child(El::new("domain").plain("includeSubdomains", Val::Bool(true))),
    );
    let paths = El::new("paths").child(El::new("root-path").plain("name", Val::Str("root")).plain("path", Val::Str("")));
    vec![("res/xml/network_security_config.xml", axml(&nsc)), ("res/xml/file_paths.xml", axml(&paths))]
}
