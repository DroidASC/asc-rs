//! What a host that keeps an engine open relies on: the stamp that says
//! whether the program's files are still the ones it read, the memory it
//! reports and gives back, and answers that do not depend on how many
//! queries run on it at once.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use asc_ark_engine::{CallQuery, CallRoots, Direction, Engine, ListOptions, Pattern, Query, Stamp};
use asc_fixture::abc::{call_graph_program, make_abc, sample_program};
use asc_fixture::hap::{Compression, Hap, SAMPLE_MODULE_JSON, make_app, make_hap};
use common::large_sample_dir;

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A later modification time, whatever the clock's resolution.
fn touch(path: &Path) {
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_modified(SystemTime::now() + Duration::from_secs(5)).unwrap();
}

fn callers_of(function: &str) -> CallQuery {
    let roots = CallRoots::Function { record: None, function: function.to_owned(), entry: None };
    CallQuery { depth: 4, ..CallQuery::new(roots, Direction::Callers) }
}

fn callees_of(function: &str) -> CallQuery {
    let roots = CallRoots::Function { record: None, function: function.to_owned(), entry: None };
    CallQuery { depth: 4, unresolved: true, ..CallQuery::new(roots, Direction::Callees) }
}

fn callers_of_leaf(pattern: &str) -> CallQuery {
    CallQuery { depth: 3, ..CallQuery::new(CallRoots::Leaf(Pattern::regex(pattern).unwrap()), Direction::Callers) }
}

/// The printed tree of `query`.
fn tree(engine: &Engine, query: &CallQuery) -> String {
    let tree = engine.call_graph(query, &AtomicBool::new(false)).unwrap();
    format!("{}\n{}", tree.lines(true).join("\n"), tree.footer())
}

/// The rows of `query`, entry by entry.
fn rows(engine: &Engine, query: &Query) -> Vec<String> {
    let mut out = Vec::new();
    engine
        .find_refs(query, &AtomicBool::new(false), &mut |batch| {
            out.extend(batch.rows.iter().map(|row| row.line(&batch.entry_name)));
        })
        .unwrap();
    out
}

#[test]
fn the_stamp_follows_the_files_of_a_lone_file() {
    let dir = tempfile::tempdir().unwrap();
    let hap = write(dir.path(), "entry.hap", &make_hap(&make_abc()));
    let engine = Engine::open(&hap).unwrap();
    assert!(engine.is_current());
    assert_eq!(*engine.stamp(), Stamp::of(&hap).unwrap());

    // Same bytes, a later time: the file was written again.
    touch(&hap);
    assert!(!engine.is_current());
    let engine = Engine::open(&hap).unwrap();
    assert!(engine.is_current());

    // Another size.
    std::fs::write(&hap, make_hap(&call_graph_program().build().bytes)).unwrap();
    assert!(!engine.is_current());

    // Gone: nothing to be current with.
    let engine = Engine::open(&hap).unwrap();
    std::fs::remove_file(&hap).unwrap();
    assert!(!engine.is_current());
    assert!(Stamp::of(&hap).is_err());
}

#[test]
fn the_stamp_follows_every_file_of_a_program() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let encrypted = sample_program().encrypted().build().bytes;
    write(&root, "entry.hap", &Hap::new().modules_abc(&encrypted).module_json(SAMPLE_MODULE_JSON).build());
    let decrypted = write(&root, "modules.abc", &make_abc());
    write(&root, "notes.txt", b"not part of the program");

    let engine = Engine::open(&root).unwrap();
    assert!(engine.is_current());
    // A file the program does not read changes nothing.
    write(&root, "more-notes.txt", b"x");
    touch(&root.join("notes.txt"));
    assert!(engine.is_current());

    // The decrypted code is replaced.
    touch(&decrypted);
    assert!(!engine.is_current());

    // A file appears, also in a directory below.
    let engine = Engine::open(&root).unwrap();
    let added = write(&root, "feature/feature.hsp", &make_hap(&make_abc()));
    assert!(!engine.is_current());

    // A file goes away.
    let engine = Engine::open(&root).unwrap();
    assert!(engine.is_current());
    std::fs::remove_file(&added).unwrap();
    assert!(!engine.is_current());

    // Paths joined with commas: each of them counts.
    let other = write(dir.path(), "calls.abc", &call_graph_program().build().bytes);
    let spec = format!("{},{}", root.display(), other.display());
    let engine = Engine::open(&spec).unwrap();
    assert!(engine.is_current());
    touch(&other);
    assert!(!engine.is_current());
}

#[test]
fn memory_use_tells_inflated_from_mapped_and_analyses() {
    let dir = tempfile::tempdir().unwrap();
    let abc = call_graph_program().build().bytes;
    let hap = Hap::new().modules_abc(&abc).module_json(SAMPLE_MODULE_JSON).build();

    // A package with stored entries is read in place: nothing on the heap.
    let stored = Engine::open(write(dir.path(), "entry.hap", &hap)).unwrap();
    let held = stored.memory_use();
    assert_eq!((held.inflated, held.analyses), (0, 0));
    assert_eq!(held.mapped, abc.len() + SAMPLE_MODULE_JSON.len(), "the code and the document, not the whole package");
    assert_eq!(held.heap(), 0);

    // A Deflate entry is inflated when the program opens.
    let deflated = Hap::new().deflate_abc().modules_abc(&abc).build();
    let held = Engine::open(write(dir.path(), "deflated.hap", &deflated)).unwrap().memory_use();
    assert!(held.inflated >= abc.len(), "{held:?}");

    // So is a Deflate inner package of an `.app`: all of it.
    let app = make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], Compression::Deflated);
    let held = Engine::open(write(dir.path(), "shop.app", &app)).unwrap().memory_use();
    assert!(held.inflated >= 2 * hap.len(), "{held:?}");
    // A stored one is read in place; only the Deflate `pack.info` is held.
    let app = make_app(&[("entry.hap", &hap)], Compression::Stored);
    let held = Engine::open(write(dir.path(), "stored.app", &app)).unwrap().memory_use();
    assert!(held.inflated < hap.len() && held.mapped >= abc.len(), "{held:?}");

    // Walks leave their analyses behind; releasing them changes no answer.
    let query = callers_of("star");
    let first = tree(&stored, &query);
    let after_walk = stored.memory_use();
    assert!(after_walk.analyses > 0, "{after_walk:?}");
    assert_eq!((after_walk.inflated, after_walk.mapped), (0, abc.len() + SAMPLE_MODULE_JSON.len()));
    assert_eq!(tree(&stored, &query), first);
    assert_eq!(stored.memory_use().analyses, after_walk.analyses, "a repeated walk computes nothing new");
    assert_eq!(stored.release_analyses(), after_walk.analyses);
    assert_eq!(stored.memory_use().analyses, 0);
    assert_eq!(stored.release_analyses(), 0);
    assert_eq!(tree(&stored, &query), first);
    assert_eq!(stored.memory_use().analyses, after_walk.analyses, "the same analyses are computed again");

    // So do `call:` searches: the captured variables they share with the walks, and the
    // callee paths the next search answers from.
    let search = Query::Call(Pattern::regex("^import:").unwrap());
    let found = rows(&stored, &search);
    assert!(!found.is_empty());
    let after_search = stored.memory_use().analyses;
    assert!(after_search > after_walk.analyses, "{after_search} after {after_walk:?}");
    assert_eq!(rows(&stored, &search), found);
    let every = Query::Call(Pattern::regex(".").unwrap());
    assert_eq!(rows(&stored, &every), rows(&Engine::open(stored.path()).unwrap(), &every));
    assert_eq!(stored.memory_use().analyses, after_search, "a repeated search computes nothing new");
    assert_eq!(stored.release_analyses(), after_search);
    assert_eq!(stored.memory_use().analyses, 0);
    assert_eq!(rows(&stored, &search), found);
    assert!(stored.memory_use().analyses > 0);
}

/// How hard [`stress`] goes.
struct Load {
    threads: usize,
    rounds: usize,
    /// The pause between two releases of the analyses.
    release_every: Duration,
}

/// Queries on one engine from `load.threads` threads at once,
/// `load.rounds` times each, while another thread keeps releasing the
/// analyses: every answer is the one a fresh engine gives alone.
fn stress(open: &(dyn Fn() -> Engine + Sync), walks: &[CallQuery], searches: &[Query], load: &Load) {
    let reference = open();
    let trees: Vec<String> = walks.iter().map(|query| tree(&reference, query)).collect();
    let found: Vec<Vec<String>> = searches.iter().map(|query| rows(&reference, query)).collect();
    let records = reference.list_classes(&ListOptions::default()).unwrap().len();
    assert!(trees.iter().any(|tree| tree.lines().count() > 2), "the walks find something");

    let engine = open();
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let releaser = scope.spawn(|| {
            let mut released = 0usize;
            while !done.load(Ordering::Relaxed) {
                released += engine.release_analyses();
                std::thread::sleep(load.release_every);
            }
            released
        });
        let workers: Vec<_> = (0..load.threads)
            .map(|worker| {
                let (engine, trees, found) = (&engine, &trees, &found);
                scope.spawn(move || {
                    for round in 0..load.rounds {
                        // Each thread starts elsewhere, so cold records are raced for.
                        for step in 0..walks.len() {
                            let at = (worker + round + step) % walks.len();
                            assert_eq!(tree(engine, &walks[at]), trees[at], "walk {at} on thread {worker}, round {round}");
                        }
                        for (at, query) in searches.iter().enumerate() {
                            assert_eq!(rows(engine, query), found[at], "search {at} on thread {worker}, round {round}");
                        }
                        assert_eq!(engine.list_classes(&ListOptions::default()).unwrap().len(), records);
                        // The estimate is read while others fill the cache.
                        let _ = engine.memory_use();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        done.store(true, Ordering::Relaxed);
        releaser.join().unwrap();
    });
    // Whatever was released under them, the walks left a whole cache or none.
    engine.release_analyses();
    assert_eq!(engine.memory_use().analyses, 0);
    for (query, expected) in walks.iter().zip(&trees) {
        assert_eq!(&tree(&engine, query), expected);
    }
}

#[test]
fn concurrent_queries_and_releases_answer_alike() {
    let dir = tempfile::tempdir().unwrap();
    let abc = call_graph_program().build().bytes;
    // Two entries, so walks also cross them.
    let path = write(dir.path(), "two.hap", &Hap::new().modules_abc(&abc).abc("widgets", &make_abc()).module_json("{}").build());
    let walks = [
        callers_of("star"),
        callers_of("helper"),
        callees_of("run"),
        callees_of("func_main_0"),
        callers_of_leaf("createhttp"),
        callers_of_leaf("."),
    ];
    let call = |pattern: &str| Query::Call(Pattern::regex(pattern).unwrap());
    let searches = [
        call("."),
        Query::string_regex("https?://").unwrap(),
        call("createhttp"),
        Query::All(vec![call("^import:"), Query::string_regex(".").unwrap()]),
    ];
    // One thread per engine query: the races are between queries.
    stress(
        &|| Engine::open(&path).unwrap().with_threads(2),
        &walks,
        &searches,
        &Load { threads: 8, rounds: 40, release_every: Duration::ZERO },
    );
}

/// The same on the large sample (skipped when it is not there), where the
/// analyses of thousands of records are raced for.
#[test]
fn concurrent_queries_answer_alike_on_the_large_sample() {
    let Some(dir) = large_sample_dir() else { return };
    let walks = [callers_of_leaf(r"^import:@ohos:net\.http"), callees_of("EntryAbility.onCreate"), callers_of("EntryAbility.onCreate")];
    let call = Query::Call(Pattern::regex(r"^import:@ohos:net\.http").unwrap());
    let searches = [call.clone(), Query::All(vec![Query::string_regex("https?://").unwrap(), call])];
    let load = Load { threads: 4, rounds: 1, release_every: Duration::from_millis(500) };
    stress(&|| Engine::open(&dir).unwrap().with_threads(4), &walks, &searches, &load);
}

/// What the analyses of the whole large sample are estimated at: of the
/// order the design document measured for the edges alone (21.6 MB), and
/// given back in full.
#[test]
fn the_analyses_of_the_large_sample_are_counted() {
    let Some(dir) = large_sample_dir() else { return };
    let engine = Engine::open(&dir).unwrap();
    let size = engine.build_call_graph(&AtomicBool::new(false)).unwrap();
    let held = engine.memory_use();
    assert_eq!(held.inflated, 0, "the decrypted code and the documents are read in place");
    assert!(held.analyses > size.edge_bytes, "scopes and importers count besides the edges: {held:?} vs {size:?}");
    assert!((20 << 20..200 << 20).contains(&held.analyses), "{held:?}");
    assert_eq!(engine.release_analyses(), held.analyses);
    assert_eq!(engine.memory_use().analyses, 0);
}
