//! The daemon answers one-shot commands exactly as the process itself would.
#![cfg(unix)]

use asc_fixture::abc::{
    annotations_program, call_graph_program, callable_names_program, class_hierarchy_program, make_abc, sample_program,
};
use asc_fixture::hap::{
    Compression, Hap, SAMPLE_MODULE_JSON, library_program, make_app, make_hap, make_library_hsp, make_routed_hap, resource_program,
};
use asc_fixture::{make_apk, make_dex};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// A private runtime directory (for the socket), a cache and a working
/// directory; the daemons started in it are stopped on drop.
struct Env {
    exe: PathBuf,
    runtime: tempfile::TempDir,
    cache: tempfile::TempDir,
    work: tempfile::TempDir,
}

/// Under /tmp: socket paths must stay short whatever `$TMPDIR` is.
fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("dmn").tempdir_in("/tmp").unwrap()
}

impl Env {
    fn new() -> Env {
        Env::with_exe(PathBuf::from(env!("CARGO_BIN_EXE_asc")))
    }

    fn with_exe(exe: PathBuf) -> Env {
        let env = Env { exe, runtime: short_tempdir(), cache: short_tempdir(), work: short_tempdir() };
        // The daemon only uses a runtime directory closed to others.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(env.runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dex = make_dex();
        std::fs::write(env.work.path().join("app.apk"), make_apk(&[("classes.dex", &dex), ("classes2.dex", &dex)], true)).unwrap();
        let broken = make_apk(&[("classes.dex", &dex), ("classes2.dex", b"this is not a dex file")], true);
        std::fs::write(env.work.path().join("broken.apk"), broken).unwrap();
        std::fs::write(env.work.path().join("rules.txt"), "# comment\nextends:java.lang.Object\n").unwrap();
        // A program of several archives (one without code).
        let sys = env.work.path().join("sys");
        std::fs::create_dir(&sys).unwrap();
        std::fs::write(sys.join("a.jar"), make_apk(&[("classes.dex", &dex)], true)).unwrap();
        std::fs::write(sys.join("b.jar"), make_apk(&[("classes.dex", &dex)], false)).unwrap();
        std::fs::write(sys.join("odexed.jar"), make_apk(&[("META-INF/MANIFEST.MF", b"m")], false)).unwrap();
        env
    }

    /// Run `args` in the working directory, through the daemon or not.
    fn run(&self, daemon: bool, args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.exe);
        cmd.current_dir(self.work.path())
            .env("ASC_CONFIG", "")
            .env("ASC_RUNTIME_DIR", self.runtime.path())
            .env("ASC_CACHE_MAX_MB", "256")
            .env_remove("ASC_DAEMON")
            .arg("--cache-dir")
            .arg(self.cache.path())
            .args(args);
        if !daemon {
            cmd.env("ASC_DAEMON", "off");
        }
        // A copy of the binary this test just wrote can still be open for
        // writing in a child another test thread forked in the meantime
        // (ETXTBSY) until that child execs: wait for it.
        for _ in 0..200 {
            match cmd.output() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => std::thread::sleep(Duration::from_millis(10)),
                other => return other.expect("run asc"),
            }
        }
        cmd.output().expect("run asc")
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.work.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// HarmonyOS programs in the working directory: packages, a bare ABC
    /// file, an `.app`, an app-store package next to its decrypted code, and
    /// directories that mix formats.
    fn with_harmony(self) -> Env {
        use std::os::unix::fs::PermissionsExt;
        let sample = make_abc();
        // With a resource index and the files it names.
        let hap = make_hap(&sample);
        self.write("entry.hap", &hap);
        self.write("labels.hap", &make_hap(&resource_program().build().bytes));
        self.write("two.hap", &Hap::new().modules_abc(&sample).abc("widgets", &sample).module_json("{}").build());
        self.write("calls.abc", &call_graph_program().build().bytes);
        self.write("marks.abc", &annotations_program().build().bytes);
        self.write("named.abc", &callable_names_program().build().bytes);
        // Read relative to the client's directory, by the client and by the daemon.
        self.write("listed.txt", b"# functions\nstar\n");
        self.write("rules.txt", b"# rules\nprop:=then\ncall:{@listed.txt}\n");
        self.write("classes.abc", &class_hierarchy_program().build().bytes);
        self.write("shop.app", &make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], Compression::Deflated));
        let encrypted = sample_program().encrypted().build().bytes;
        let store = Hap::new().modules_abc(&encrypted).abc("widgets", &sample).module_json(SAMPLE_MODULE_JSON).build();
        // Encrypted code alone, and next to the decrypted file that stands in for it.
        self.write("store.hap", &store);
        self.write("store/entry.hap", &store);
        self.write("store/modules.abc", &sample);
        // A package that does not open, among others and alone.
        self.write("pkgs/a.hap", &hap);
        self.write("pkgs/b.hap", b"PK not a zip");
        self.write("broken.hap", b"PK not a zip");
        // A package that cannot be read, among others.
        self.write("locked/a.hap", &hap);
        self.write("locked/b.hap", &hap);
        std::fs::set_permissions(self.work.path().join("locked/b.hap"), std::fs::Permissions::from_mode(0o000)).unwrap();
        // Other spellings of a program: its entry is named after the file as given.
        std::os::unix::fs::symlink("calls.abc", self.work.path().join("link.abc")).unwrap();
        std::os::unix::fs::symlink("store", self.work.path().join("store-link")).unwrap();
        // A module with a route table and long strings, next to the package a
        // route leads into; both carry the bytes of one pack.info.
        self.write("routed/entry.hap", &make_routed_hap());
        self.write("routed/lib.hsp", &make_library_hsp());
        // Two app-store packages, each next to its decrypted code, and one without.
        let library = library_program().build().bytes;
        let library_store = Hap::new().modules_abc(&library_program().encrypted().build().bytes).module_json("{}").build();
        self.write("stores/a.hap", &store);
        self.write("stores/a.hap.abc", &sample);
        self.write("stores/b.hsp", &library_store);
        self.write("stores/b.hsp.abc", &library);
        self.write("stores-partial/a.hap", &store);
        self.write("stores-partial/a.hap.abc", &sample);
        self.write("stores-partial/b.hsp", &library_store);
        self.write("stores-partial/b.hsp.abc", &library);
        self.write("stores-partial/c.hap", &store);
        // DEX code next to HarmonyOS files stays a DEX program.
        self.write("mixed/app.apk", &make_apk(&[("classes.dex", &make_dex())], true));
        self.write("mixed/entry.hap", &hap);
        // A debug build with its source maps, as a file and unpacked into a
        // directory; two unpacked packages side by side; an `.app` in a zip.
        let debug = asc_fixture::hap::make_debug_hap(&sample);
        self.write("debug.hap", &debug);
        asc_fixture::hap::unpack(&debug, &self.work.path().join("unpacked"));
        asc_fixture::hap::unpack(&hap, &self.work.path().join("apps/entry"));
        asc_fixture::hap::unpack(&make_library_hsp(), &self.work.path().join("apps/library"));
        let app = make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], Compression::Deflated);
        self.write("bundle.zip", &Hap::new().entry("out/shop.app", &app, Compression::Deflated).build());
        self
    }

    fn start(&self) -> u32 {
        let out = self.run(true, &["daemon", "start"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        pid_of(&String::from_utf8_lossy(&out.stdout))
    }

    fn status(&self) -> String {
        String::from_utf8_lossy(&self.run(true, &["daemon", "status"]).stdout).into_owned()
    }

    /// Requests served, summed over the running daemons.
    fn served(&self) -> usize {
        self.status().lines().filter_map(|l| l.split(", ").nth(2)?.split(' ').next()?.parse::<usize>().ok()).sum()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(true, &["daemon", "stop"]);
    }
}

fn pid_of(status: &str) -> u32 {
    status
        .strip_prefix("pid ")
        .and_then(|s| s.split(',').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no pid in {status:?}"))
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        || Command::new("kill").args(["-0", &pid.to_string()]).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
}

#[test]
fn daemon_output_is_byte_identical() {
    let env = Env::new();
    env.start();
    let cases: &[&[&str]] = &[
        &["findrefs", "app.apk", "string", "token", "--threads", "1"],
        &["findrefs", "app.apk", "string", "a.b(", "--literal", "--threads", "1"],
        &["findrefs", "app.apk", "type", "example.Test", "--threads", "1"],
        &["findrefs", "app.apk", "method", "first", "--class", "example.Test", "--threads", "1"],
        &["findrefs", "app.apk", "method", "--threads", "1"],
        &["findrefs", "app.apk", "field", "x", "--threads", "1"],
        &["findrefs", "app.apk", "extends", "java.lang.Object", "--threads", "1"],
        &["findrefs", "app.apk", "impl", "java.lang.Runnable", "--threads", "1"],
        &["findrefs", "app.apk", "all", "string:tok", "literal:token", "--threads", "1"],
        &["findrefs", "app.apk", "rules", "string:token", "string:nothing & literal:token", "--file", "rules.txt", "--threads", "1"],
        &["findrefs", "app.apk", "--context", "2", "string", "token", "--threads", "1"],
        &["findrefs", "app.apk", "--context-method", "string", "token", "--threads", "1"],
        &["findrefs", "broken.apk", "string", "token", "--threads", "1"],
        &["getclass", "app.apk", "example.Test", "--threads", "1"],
        &["getclass", "app.apk", "Lnope/Missing;"],
        &["disassemble", "app.apk", "example.Test", "--threads", "1"],
        &["listclass", "app.apk"],
        &["listclass", "app.apk", "--prefix", "example"],
        &["getmanifest", "app.apk"],
        &["manifest-summary", "app.apk"],
        &["resources", "app.apk"],
        &["xml", "app.apk", "res/xml/none.xml"],
        &["callgraph", "app.apk", "example.Test", "first", "--virtual"],
        &["callgraph", "app.apk", "example.Test", "nope"],
        &["hierarchy", "app.apk", "java.lang.Object", "--method", "second"],
        // Cut output (the spill file is named by content, so both name the same one).
        &["findrefs", "app.apk", "string", "token", "--limit", "1"],
        &["findrefs", "app.apk", "string", "token", "--offset", "1", "--max-bytes", "4096"],
        &["findrefs", "app.apk", "rules", "string:token", "extends:java.lang.Object", "--limit", "2"],
        &["getclass", "app.apk", "example.Test", "--limit", "3"],
        &["listclass", "app.apk", "--offset", "9"],
        &["callgraph", "app.apk", "example.Test", "first", "--limit", "1", "--spill-mb", "0"],
        // Programs: a directory, and relative paths joined with commas.
        &["findrefs", "sys", "string", "token", "--threads", "1"],
        &["findrefs", "app.apk,sys/b.jar", "string", "token", "--threads", "1"],
        &["listclass", "sys"],
        &["callgraph", "sys", "example.Test", "first"],
        // Declined by the daemon (the error names the path as given).
        &["findrefs", "missing.apk", "string", "token"],
    ];
    let before = env.served();
    for args in cases {
        let local = env.run(false, args);
        let remote = env.run(true, args);
        assert_eq!(String::from_utf8_lossy(&remote.stdout), String::from_utf8_lossy(&local.stdout), "stdout of {args:?}");
        assert_eq!(String::from_utf8_lossy(&remote.stderr), String::from_utf8_lossy(&local.stderr), "stderr of {args:?}");
        assert_eq!(remote.status.code(), local.status.code(), "exit status of {args:?}");
    }
    let served = env.served() - before;
    assert_eq!(served, cases.len() - 1, "every case but the missing APK ran in the daemon:\n{}", env.status());
    // Exit status 2 and 1 came through as well.
    assert_eq!(env.run(true, &["findrefs", "broken.apk", "string", "token"]).status.code(), Some(2));
    assert_eq!(env.run(true, &["getclass", "app.apk", "Lnope/Missing;"]).status.code(), Some(1));
}

/// The cases of a byte-for-byte comparison: each runs in its own process and
/// through the daemon.
fn assert_same_output(env: &Env, cases: &[&[&str]]) {
    for args in cases {
        let local = env.run(false, args);
        let remote = env.run(true, args);
        assert_eq!(String::from_utf8_lossy(&remote.stdout), String::from_utf8_lossy(&local.stdout), "stdout of {args:?}");
        assert_eq!(String::from_utf8_lossy(&remote.stderr), String::from_utf8_lossy(&local.stderr), "stderr of {args:?}");
        assert_eq!(remote.status.code(), local.status.code(), "exit status of {args:?}");
    }
}

#[test]
fn daemon_output_is_byte_identical_for_harmony_programs() {
    let env = Env::new().with_harmony();
    env.start();
    let cases: &[&[&str]] = &[
        &["listclass", "entry.hap"],
        &["listclass", "entry.hap", "--all"],
        &["listclass", "entry.hap", "--prefix", "&entry/src/main/ets/pages"],
        &["listclass", "two.hap"],
        &["getclass", "entry.hap", "pages/Index"],
        &["getclass", "entry.hap", "pages/Index", "--method", "Index.build"],
        &["getclass", "entry.hap", "pages/Missing"],
        &["getclass", "two.hap", "pages/Index"],
        &["getclass", "two.hap", "pages/Index", "--entry", "ets/widgets.abc"],
        &["getclass", "entry.hap", "pages/Index", "--dump-dex", "x.dex"],
        &["disassemble", "entry.hap", "pages/Index"],
        &["findrefs", "entry.hap", "string", "https?://", "--threads", "1"],
        &["findrefs", "entry.hap", "string", "testTag"],
        &["findrefs", "entry.hap", "string", "nothing-like-this"],
        &["findrefs", "entry.hap", "prop", "createHttp", "--exact", "--access", "call"],
        &["findrefs", "entry.hap", "global", "console", "--exact"],
        &["findrefs", "entry.hap", "import", "@ohos:net\\.http"],
        &["findrefs", "entry.hap", "import", ".", "--requests"],
        &["findrefs", "entry.hap", "method", "Index.build", "--exact"],
        &["findrefs", "entry.hap", "number", "0x1d4b42"],
        &["findrefs", "entry.hap", "call", "^import:@ohos:net\\.http"],
        &["findrefs", "entry.hap", "all", "string:^https://", "call:createHttp"],
        &["findrefs", "entry.hap", "type", "example.Test"],
        &["findrefs", "entry.hap", "--context", "2", "string", "testTag"],
        &["getmanifest", "entry.hap"],
        &["getmanifest", "entry.hap", "--file", "pack.info"],
        &["manifest-summary", "entry.hap"],
        &["manifest-summary", "entry.hap", "--json"],
        &["hierarchy", "entry.hap", "Index"],
        &["hierarchy", "entry.hap", "UIAbility", "--method", "onCreate"],
        &["hierarchy", "two.hap", "EntryAbility", "--supers"],
        &["hierarchy", "two.hap", "EntryAbility", "--supers", "--entry", "ets/widgets.abc"],
        &["hierarchy", "classes.abc", "Local"],
        &["hierarchy", "classes.abc", "Base", "--method", "run"],
        &["hierarchy", "classes.abc", "pages/App->GrandChild", "--supers", "--method", "run"],
        &["hierarchy", "classes.abc", "^import:", "--depth", "1", "--max-nodes", "3"],
        &["hierarchy", "classes.abc", "Card", "--supers"],
        &["hierarchy", "classes.abc", "Nowhere"],
        &["hierarchy", "classes.abc", "global:Error", "--supers"],
        &["hierarchy", "classes.abc", "Local", "--limit", "2"],
        &["hierarchy", "store.hap", "Index"],
        &["resources", "entry.hap"],
        &["resources", "entry.hap", "string/EntryAbility_label"],
        &["resources", "entry.hap", "16777218", "--resolve"],
        &["resources", "entry.hap", "--search", "^https?://", "--in", "value"],
        &["resources", "entry.hap", "--search", ".", "--limit", "3"],
        &["resources", "entry.hap", "string/nothing"],
        &["resources", "entry.hap", "--search", "x", "--in", "both"],
        &["resources", "shop.app", "color/brand"],
        &["resources", "pkgs", "--search", "label", "--in", "name"],
        &["resources", "two.hap"],
        &["resources", "calls.abc"],
        &["xml", "entry.hap", "$profile:main_pages"],
        &["xml", "entry.hap", "resources/base/profile/main_pages.json"],
        &["xml", "entry.hap", "$media:icon"],
        &["xml", "entry.hap", "res/xml/nothing.xml"],
        &["xml", "shop.app", "$profile:main_pages"],
        &["xml", "calls.abc", "module.json"],
        &["getclass", "entry.hap", "pages/Index", "--res-names"],
        &["getclass", "labels.hap", "pages/Labels", "--res-names"],
        &["getclass", "labels.hap", "pages/Labels", "--method", "labels", "--res-names"],
        &["getmanifest", "entry.hap", "--resolve"],
        // A bare ABC file; its errors name the path as given.
        &["listclass", "calls.abc"],
        &["manifest-summary", "calls.abc"],
        &["getmanifest", "calls.abc", "--file", "pack.info"],
        &["callgraph", "calls.abc", "star"],
        &["callgraph", "calls.abc", "star", "--depth", "3", "--from", "method:=cb"],
        // Rules at the ends of a walk, and what they leave out.
        &["callgraph", "calls.abc", "star", "--depth", "3", "--from", "prop:=then"],
        &["callgraph", "calls.abc", "star", "--from", "method:=make"],
        &["callgraph", "calls.abc", "star", "--unless", "method:=helper"],
        &["callgraph", "calls.abc", "star", "--unless", "global:=console & prop:=log", "--unless", "method:^func_main"],
        &["callgraph", "calls.abc", "--to", "prop:=log", "--depth", "1"],
        &["callgraph", "calls.abc", "--to", "call:{method:=star} & !method:=helper"],
        &["callgraph", "calls.abc", "--from", "method:=cb"],
        &["callgraph", "calls.abc", "--to", "prop:=nowhere"],
        &["callgraph", "calls.abc", "star", "--unless", "type:x"],
        // Excluded conditions, sets of functions, rule sets and the code around a hit.
        &["findrefs", "calls.abc", "all", "prop:=make", "prop:=then", "!prop:=size"],
        &["findrefs", "calls.abc", "all", "prop:=get", "--none", "prop:=then"],
        &["findrefs", "calls.abc", "all", "method:helper", "!prop:=then"],
        &["findrefs", "calls.abc", "all", "!prop:=then"],
        &["findrefs", "calls.abc", "call", "{method:=star}"],
        &["findrefs", "calls.abc", "all", "call:{call:{method:=star}}", "!method:=run"],
        &["findrefs", "calls.abc", "call", "{@listed.txt}"],
        &["findrefs", "calls.abc", "call", "{@nowhere.txt}"],
        &["findrefs", "calls.abc", "prop", "=then"],
        &["findrefs", "calls.abc", "rules", "prop:=then & !prop:=size", "call:{method:=star}", "prop:=nope"],
        &["findrefs", "calls.abc", "rules", "--file", "rules.txt", "--context", "1"],
        &["findrefs", "calls.abc", "rules"],
        &["findrefs", "calls.abc", "prop", "then", "--exact", "--context", "1"],
        // Annotations of the program: their interfaces, the strings in them; calls that name their method.
        &["listclass", "marks.abc"],
        &["listclass", "marks.abc", "--all"],
        &["getclass", "marks.abc", "pages/Pay.Route"],
        &["getclass", "marks.abc", "index"],
        &["findrefs", "marks.abc", "string", "."],
        &["findrefs", "marks.abc", "string", "pay", "--context", "1"],
        &["findrefs", "marks.abc", "rules", "string:pay", "string:^/pay$ & !string:opens"],
        &["findrefs", "named.abc", "prop", "."],
        &["findrefs", "named.abc", "prop", "cut", "--exact", "--access", "read"],
        &["findrefs", "named.abc", "prop", "cut", "--exact", "--access", "call", "--context", "1"],
        &["findrefs", "named.abc", "all", "prop:=fold", "prop:=close", "--context", "0"],
        &["findrefs", "calls.abc", "prop", ".", "--context", "method", "--limit", "3"],
        &["findrefs", "calls.abc", "all", "prop:=make", "prop:=then", "--context", "0"],
        &["findrefs", "entry.hap", "string", "https?://", "--context-method"],
        &["callgraph", "calls.abc", "pages/App", "run", "--callees", "--depth", "1", "--unresolved"],
        &["callgraph", "calls.abc", "--to", "call:createhttp"],
        &["callgraph", "calls.abc", "--to", "call:^nothing$"],
        &["callgraph", "calls.abc", "nope"],
        &["callgraph", "calls.abc", "star", "--virtual"],
        // Cut output (the spill file is named by content, so both name the same one).
        &["listclass", "entry.hap", "--limit", "1"],
        &["findrefs", "entry.hap", "prop", ".", "--offset", "1", "--max-bytes", "4096"],
        &["callgraph", "calls.abc", "star", "--limit", "3", "--spill-mb", "0"],
        // An `.app` (its packages inflated), and encrypted code: left out
        // (exit status 2), or served from the decrypted file next to it.
        &["listclass", "shop.app"],
        &["manifest-summary", "shop.app"],
        &["findrefs", "shop.app", "string", "testTag"],
        &["findrefs", "store.hap", "string", "testTag"],
        &["callgraph", "store.hap", "Index.build", "--callees", "--depth", "1"],
        &["listclass", "store"],
        &["findrefs", "store", "string", "testTag"],
        &["manifest-summary", "store"],
        // Decrypted files next to several packages are one note; a package
        // without one is still a warning and exit status 2.
        &["findrefs", "stores", "string", "shared|testTag"],
        &["manifest-summary", "stores"],
        &["findrefs", "stores-partial", "string", "shared|testTag"],
        &["findrefs", "stores-partial", "string", "testTag", "--entry", "a.hap"],
        &["findrefs", "stores-partial", "string", "testTag", "--entry", "c.hap"],
        &["listclass", "stores-partial", "--entry", "b.hsp"],
        // Pages and routes joined to records, across packages; one pack.info
        // for the packages that share its bytes; long strings cut.
        &["manifest-summary", "routed"],
        &["manifest-summary", "routed", "--json"],
        &["manifest-summary", "routed", "--file", "pack.info"],
        &["manifest-summary", "routed", "--limit", "3", "--offset", "10"],
        &["getmanifest", "routed", "--file", "pack.info"],
        &["getmanifest", "shop.app", "--file", "pack.info"],
        &["manifest-summary", "pkgs"],
        &["findrefs", "routed", "string", "example\\.com/far"],
        &["findrefs", "routed", "string", "example.com/far", "--literal", "--entry", "entry.hap"],
        &["findrefs", "routed", "all", "string:far/operand", "literal:far/item"],
        // Kept to one entry or package; an entry that is not there.
        &["findrefs", "two.hap", "string", "testTag", "--entry", "ets/widgets.abc"],
        &["findrefs", "two.hap", "--entry", "two.hap", "import", ".", "--requests"],
        &["findrefs", "pkgs", "number", "0x1d4b42", "--entry", "a.hap"],
        &["findrefs", "pkgs", "string", "nothing-like-this", "--entry", "a.hap"],
        &["findrefs", "pkgs", "string", "testTag", "--entry", "nope.hap"],
        &["listclass", "two.hap", "--entry", "ets/widgets.abc"],
        &["listclass", "pkgs", "--entry", "nope.hap"],
        // Programs of several files: a directory with a package that does
        // not open, relative paths joined with commas.
        &["listclass", "pkgs"],
        &["findrefs", "entry.hap,calls.abc", "string", "testTag"],
        &["listclass", "store/modules.abc,two.hap"],
        &["listclass", "locked"],
        // A link to a program and a roundabout path: rows name the file as given.
        &["findrefs", "link.abc", "call", "."],
        &["findrefs", "calls.abc", "call", "."],
        &["findrefs", "store/../calls.abc", "call", "."],
        &["findrefs", "store-link", "string", "testTag"],
        &["manifest-summary", "store/../link.abc"],
        // DEX code next to HarmonyOS files: a DEX program, which says so.
        &["listclass", "mixed"],
        &["findrefs", "mixed", "string", "token", "--threads", "1"],
        // A package unpacked into a directory answers as the file does; the
        // source maps of a debug build name source files and lines.
        &["listclass", "unpacked"],
        &["manifest-summary", "unpacked"],
        &["manifest-summary", "unpacked", "--json"],
        &["manifest-summary", "debug.hap"],
        &["resources", "unpacked", "string/EntryAbility_label"],
        &["xml", "unpacked", "$profile:main_pages"],
        &["xml", "unpacked", "ets/sourceMaps.map"],
        &["xml", "unpacked", "../debug.hap"],
        &["getclass", "unpacked", "pages/Index"],
        &["getclass", "debug.hap", "pages/Index", "--method", "Index.build"],
        // Every line of the debug info, with and without a source map.
        &["getclass", "debug.hap", "pages/Index", "--lines"],
        &["getclass", "unpacked", "pages/Index", "--method", "Index.build", "--lines"],
        &["disassemble", "entry.hap", "pages/Index", "--debuginfo"],
        &["disassemble", "entry.hap", "pages/Index", "--lines", "-o", "lines.pa"],
        &["getclass", "debug.hap", "entryability/EntryAbility"],
        &["findrefs", "unpacked", "string", "testTag"],
        &["callgraph", "unpacked", "pages/Index", "Index.build", "--callees"],
        &["manifest-summary", "apps"],
        &["resources", "apps", "--search", "label", "--in", "name"],
        &["findrefs", "apps", "string", ".", "--entry", "library"],
        // Packages inside zips inside a zip, named by the whole path.
        &["listclass", "bundle.zip"],
        &["manifest-summary", "bundle.zip"],
        &["findrefs", "bundle.zip", "string", "testTag", "--entry", "out/shop.app/feature.hap"],
        &["xml", "bundle.zip", "out/shop.app/entry.hap/resources/base/profile/main_pages.json"],
        // Declined by the daemon (the error names the path as given).
        &["listclass", "missing.hap"],
        &["listclass", "broken.hap"],
        &["findrefs", "missing.hap", "--context", "2", "string", "x"],
    ];
    let before = env.served();
    assert_same_output(&env, cases);
    let served = env.served() - before;
    assert_eq!(served, cases.len() - 3, "every case but the programs that do not open ran in the daemon:\n{}", env.status());
    // Exit status 2 and 1 came through as well, and the notes of a program.
    let partial = env.run(true, &["findrefs", "store.hap", "string", "testTag"]);
    assert_eq!(partial.status.code(), Some(2), "{partial:?}");
    assert!(String::from_utf8_lossy(&partial.stderr).contains("is encrypted"), "{partial:?}");
    assert_eq!(env.run(true, &["getclass", "entry.hap", "pages/Missing"]).status.code(), Some(1));
    let paired = env.run(true, &["listclass", "store"]);
    assert_eq!(
        String::from_utf8_lossy(&paired.stderr),
        "# note: entry.hap/ets/modules.abc is encrypted in its package; served from the decrypted modules.abc\n",
        "{paired:?}"
    );
    let several = env.run(true, &["listclass", "stores"]);
    assert_eq!(
        String::from_utf8_lossy(&several.stderr),
        "# note: 2 encrypted abc entries are served from the decrypted files next to them (manifest-summary names each: its `abc` lines)\n",
        "{several:?}"
    );
    let partial = env.run(true, &["findrefs", "stores-partial", "string", "testTag"]);
    assert_eq!(partial.status.code(), Some(2), "{partial:?}");
    assert_eq!(String::from_utf8_lossy(&partial.stderr).lines().filter(|line| line.starts_with("# ")).count(), 2, "{partial:?}");
    assert_eq!(env.run(true, &["findrefs", "stores-partial", "string", "testTag", "--entry", "a.hap"]).status.code(), Some(0));
}

/// The resident engine of a HarmonyOS program is not served once a file of
/// the program changed, appeared or went away.
#[test]
fn a_changed_harmony_program_is_opened_again() {
    let env = Env::new().with_harmony();
    env.start();
    let records = |program: &str| {
        let out = env.run(true, &["listclass", program]);
        assert!(out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let local = |program: &str| String::from_utf8_lossy(&env.run(false, &["listclass", program]).stdout).into_owned();
    let before = env.served();

    // A file replaced by one of another size.
    let first = records("entry.hap");
    assert!(first.contains("pages/Index") && !first.contains("pages/App"), "{first}");
    env.write("entry.hap", &make_hap(&call_graph_program().build().bytes));
    let second = records("entry.hap");
    assert!(second.contains("pages/App") && !second.contains("pages/Index"), "the daemon answered from the replaced file:\n{second}");
    assert_eq!(second, local("entry.hap"));

    // The same size, a later modification time.
    let path = env.work.path().join("calls.abc");
    let warm = records("calls.abc");
    let file = std::fs::File::options().write(true).open(&path).unwrap();
    file.set_modified(std::time::SystemTime::now() + Duration::from_secs(5)).unwrap();
    drop(file);
    assert_eq!(records("calls.abc"), warm);

    // A directory: a file appears, then another goes away.
    let paired = records("store");
    env.write("store/calls.abc", &call_graph_program().build().bytes);
    let grown = records("store");
    assert!(grown.contains("pages/App") && grown != paired, "the daemon did not see the new file:\n{grown}");
    assert_eq!(grown, local("store"));
    std::fs::remove_file(env.work.path().join("store/modules.abc")).unwrap();
    let shrunk = env.run(true, &["listclass", "store"]);
    let shrunk_local = env.run(false, &["listclass", "store"]);
    assert_eq!(shrunk.stdout, shrunk_local.stdout);
    assert_eq!(shrunk.stderr, shrunk_local.stderr, "the encrypted entry has nothing standing in for it now");
    assert!(String::from_utf8_lossy(&shrunk.stderr).contains("is encrypted"), "{shrunk:?}");

    // DEX code appears next to the packages: a DEX program from then on.
    assert!(records("pkgs").contains("pages/Index"));
    env.write("pkgs/app.apk", &make_apk(&[("classes.dex", &make_dex())], true));
    assert_eq!(records("pkgs"), "Lexample/Test;\n");
    // And goes away again.
    std::fs::remove_file(env.work.path().join("pkgs/app.apk")).unwrap();
    assert_eq!(records("pkgs"), local("pkgs"));
    assert_eq!(env.served() - before, 10, "every command ran in the daemon:\n{}", env.status());
}

/// Requests on one HarmonyOS program run side by side on its one engine and
/// answer as each would alone.
#[test]
fn parallel_requests_share_a_harmony_engine() {
    let env = Env::new().with_harmony();
    env.start();
    let cases: &[&[&str]] = &[
        &["callgraph", "calls.abc", "star"],
        &["callgraph", "calls.abc", "pages/App", "run", "--callees", "--unresolved"],
        &["callgraph", "calls.abc", "--to", "call:createhttp"],
        &["findrefs", "calls.abc", "call", "."],
        &["listclass", "calls.abc"],
    ];
    let expected: Vec<Output> = cases.iter().map(|args| env.run(false, args)).collect();
    let before = env.served();
    let rounds = 6;
    std::thread::scope(|scope| {
        let env = &env;
        let clients: Vec<_> =
            (0..rounds * cases.len()).map(|i| scope.spawn(move || (i % cases.len(), env.run(true, cases[i % cases.len()])))).collect();
        for client in clients {
            let (case, out) = client.join().unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&expected[case].stdout),
                "stdout of {:?}",
                cases[case]
            );
            assert_eq!(out.stderr, expected[case].stderr, "stderr of {:?}", cases[case]);
            assert_eq!(out.status.code(), expected[case].status.code());
        }
    });
    assert_eq!(env.served() - before, rounds * cases.len(), "every request ran in the daemon:\n{}", env.status());
    let status = env.status();
    assert!(status.contains(", 1 APKs open, "), "one engine served them all: {status}");
}

/// What open HarmonyOS programs hold on the heap counts against the memory
/// budget: beyond their share of it the least recently used one closes, and
/// opens again when it is named.
#[test]
fn harmony_programs_beyond_the_memory_share_close() {
    let env = Env::new().with_harmony();
    // 700 KiB of padding in each inner package: held inflated while the
    // `.app` is open. Two do not fit in half of a 2 MiB budget.
    let padding: Vec<u8> = (0..700u32 << 10).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let hap = Hap::new().modules_abc(&make_abc()).module_json(SAMPLE_MODULE_JSON).entry("resources.bin", &padding, Compression::Stored);
    for name in ["one.app", "two.app"] {
        env.write(name, &make_app(&[("entry.hap", &hap.build())], Compression::Deflated));
    }
    let run = |program: &str| {
        let out = env.run(true, &["--memory-mb", "2", "listclass", program]);
        assert!(out.status.success(), "{out:?}");
        out.stdout
    };
    let open = || {
        let out = env.run(true, &["--memory-mb", "2", "daemon", "status"]);
        let status = String::from_utf8_lossy(&out.stdout).into_owned();
        let count = status
            .lines()
            .filter(|line| line.contains("memory cache 0 of 2 MiB"))
            .find_map(|line| line.split(", ").find_map(|part| part.strip_suffix(" APKs open")).and_then(|n| n.parse::<usize>().ok()));
        count.unwrap_or_else(|| panic!("no daemon with a 2 MiB memory cache in {status:?}"))
    };
    let small = run("entry.hap");
    let one = run("one.app");
    assert_eq!(open(), 2, "a small program stays open next to a large one");
    let two = run("two.app");
    assert_eq!(open(), 2, "the older large program closed");
    assert_eq!(run("one.app"), one, "a closed program opens again");
    assert_eq!(open(), 2);
    assert_eq!(run("entry.hap"), small);
    assert_eq!(run("two.app"), two);
}

#[test]
fn output_files_land_relative_to_the_client() {
    let env = Env::new();
    env.start();
    let w = env.work.path();
    for (daemon, name) in [(false, "local"), (true, "remote")] {
        let o = format!("{name}.txt");
        let dex = format!("{name}.dex");
        assert!(env.run(daemon, &["findrefs", "app.apk", "string", "token", "--threads", "1", "-o", &o]).status.success());
        assert!(env.run(daemon, &["getclass", "app.apk", "example.Test", "--threads", "1", "--dump-dex", &dex]).status.success());
        let out = env.run(daemon, &["findrefs", "app.apk", "string", "token", "-o", "no/such/dir/x.txt"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).starts_with("Error: cannot write no/such/dir/x.txt:"), "{out:?}");
    }
    assert_eq!(std::fs::read(w.join("remote.txt")).unwrap(), std::fs::read(w.join("local.txt")).unwrap());
    assert_eq!(std::fs::read(w.join("remote.dex")).unwrap(), std::fs::read(w.join("local.dex")).unwrap());
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &str| std::fs::metadata(w.join(p)).unwrap().permissions().mode();
    assert_eq!(mode("remote.txt"), mode("local.txt"), "the client's umask applies");
}

#[test]
fn a_relative_cache_dir_is_the_clients() {
    let env = Env::new();
    let run = |daemon: bool, cache: &str| {
        let mut cmd = Command::new(&env.exe);
        cmd.current_dir(env.work.path())
            .env("ASC_CONFIG", "")
            .env("ASC_RUNTIME_DIR", env.runtime.path())
            .env_remove("ASC_DAEMON")
            .args(["findrefs", "app.apk", "string", "token", "--threads", "1", "--limit", "1"])
            .args(["--set", &format!("cache.dir={cache}")]);
        if !daemon {
            cmd.env("ASC_DAEMON", "off");
        }
        cmd.output().expect("run asc")
    };
    for (daemon, cache) in [(false, "local-cache"), (true, "remote-cache")] {
        let out = run(daemon, cache);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{out:?}");
        // The cut output goes to the cache's out/, below the client's directory.
        let spilled = env.work.path().join(cache).join("out");
        assert!(stdout.contains(&spilled.display().to_string()), "{stdout}");
        assert!(std::fs::read_dir(&spilled).unwrap().next().is_some());
    }
}

#[test]
fn first_command_starts_the_daemon_and_off_bypasses_it() {
    let env = Env::new();
    let off = env.run(false, &["listclass", "app.apk"]);
    assert!(env.status().starts_with("no daemon"), "ASC_DAEMON=off starts nothing");
    let first = env.run(true, &["listclass", "app.apk"]);
    assert_eq!(first.stdout, off.stdout);
    let t0 = Instant::now();
    while env.status().starts_with("no daemon") {
        assert!(t0.elapsed() < Duration::from_secs(10), "no daemon came up");
        std::thread::sleep(Duration::from_millis(20));
    }
    let before = env.served();
    assert_eq!(env.run(true, &["listclass", "app.apk"]).stdout, off.stdout);
    assert_eq!(env.served(), before + 1);
    // Not forwarded: --debug and --no-cache.
    env.run(true, &["listclass", "app.apk", "--debug"]);
    env.run(true, &["--no-cache", "listclass", "app.apk"]);
    assert_eq!(env.served(), before + 1);
}

#[test]
fn a_replaced_binary_retires_the_old_daemon() {
    let bin = short_tempdir();
    let exe = bin.path().join("asc");
    std::fs::copy(env!("CARGO_BIN_EXE_asc"), &exe).unwrap();
    let env = Env::with_exe(exe.clone());
    let old = env.start();
    // A new build at the same path (one more byte changes its identity).
    let mut bytes = std::fs::read(&exe).unwrap();
    bytes.push(0);
    let next = bin.path().join("asc.new");
    std::fs::write(&next, bytes).unwrap();
    std::fs::set_permissions(&next, std::fs::metadata(&exe).unwrap().permissions()).unwrap();
    std::fs::rename(&next, &exe).unwrap();
    let new = env.start();
    assert_ne!(new, old);
    let t0 = Instant::now();
    while alive(old) {
        assert!(t0.elapsed() < Duration::from_secs(10), "the old build's daemon {old} is still running");
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = env.status();
    assert_eq!(status.lines().count(), 1, "{status}");
    assert_eq!(pid_of(&status), new);
}

#[test]
fn idle_and_wait_times_come_from_the_environment() {
    let env = Env::new();
    // No wait: the first command runs itself while the daemon starts.
    let mut cmd = Command::new(&env.exe);
    cmd.current_dir(env.work.path())
        .env("ASC_CONFIG", "")
        .env("ASC_RUNTIME_DIR", env.runtime.path())
        .env("ASC_CACHE_MAX_MB", "256")
        .env("ASC_DAEMON_WAIT_MS", "0")
        .env("ASC_DAEMON_IDLE", "1")
        .env_remove("ASC_DAEMON")
        .arg("--cache-dir")
        .arg(env.cache.path())
        .args(["listclass", "app.apk"]);
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pid = {
        let t0 = Instant::now();
        loop {
            let status = env.status();
            if status.starts_with("pid ") {
                break pid_of(&status);
            }
            assert!(t0.elapsed() < Duration::from_secs(5), "daemon never came up: {status:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    // `daemon status` is not a request: the daemon exits a second after it started.
    let t0 = Instant::now();
    while alive(pid) {
        assert!(t0.elapsed() < Duration::from_secs(10), "daemon {pid} still up with ASC_DAEMON_IDLE=1");
        std::thread::sleep(Duration::from_millis(50));
    }
}
