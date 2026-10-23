//! Engine support for sweeps over many APKs, whose DEX entries the caller
//! schedules ([`Engine::search_target`]): L3 results per APK, and identical
//! DEX entries across the APKs of one sweep searched once.
//!
//! App variants, re-signed copies and split builds often carry byte-identical
//! `classes*.dex`. While planning, every entry claims its content key, the
//! CRC-32 and size the central directory already records. The first claimant
//! of a key leads and searches; the others follow and reuse its rows, renamed
//! to their own entry. The CRC-32, the size and the DEX header's checksum and
//! signature are all whatever the APK's author wrote, so an APK could claim
//! another one's DEX to hide its own code from an audit: a follower reuses
//! rows only when the SHA-256 of its inflated bytes equals the leader's, and
//! searches by itself otherwise. That costs a read (an inflate for a deflated
//! entry) but still saves the parse, the index build and the scan.

use crate::{tiers, CompiledQuery, Engine, FindOptions, Job, Query, RefBatch, RefContext, SearchTarget, WriteJob};
use asc_apk::Entry;
use asc_cache::Tier;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

/// SHA-256 of an entry's inflated bytes.
type Ident = [u8; 32];

/// Content keys claimed by the entries of one sweep.
#[derive(Default)]
pub struct DexDedup {
    groups: Mutex<HashMap<(u32, u64), Arc<Group>>>,
    shared: Arc<AtomicUsize>,
}

/// One entry's part in a [`DexDedup`].
#[derive(Clone)]
pub struct Claim {
    group: Arc<Group>,
    lead: bool,
    /// The sweep's count of entries answered by their leader.
    shared: Arc<AtomicUsize>,
}

#[derive(Default)]
struct Group {
    members: AtomicUsize,
    /// Set once by the leader: `None` when it has nothing to share.
    result: Mutex<Option<Option<Arc<Shared>>>>,
    ready: Condvar,
}

struct Shared {
    ident: Ident,
    batch: RefBatch,
}

impl DexDedup {
    pub fn new() -> DexDedup {
        DexDedup::default()
    }

    /// Claim `entry`'s content. Claim every entry of the sweep before
    /// searching any of them, so a leader knows whether anyone follows.
    pub fn claim(&self, entry: &Entry) -> Claim {
        let mut groups = self.groups.lock().unwrap();
        let group = groups.entry((entry.crc32, entry.uncomp_size)).or_default();
        let lead = group.members.fetch_add(1, Ordering::Relaxed) == 0;
        Claim { group: Arc::clone(group), lead, shared: Arc::clone(&self.shared) }
    }

    /// Whether a claim follows another entry (and is cheap to search).
    pub fn follows(claim: &Claim) -> bool {
        !claim.lead
    }

    /// Entries answered from another APK's search so far.
    pub fn shared(&self) -> usize {
        self.shared.load(Ordering::Relaxed)
    }
}

/// Publishes `None` if the leader unwinds before publishing, so followers
/// never wait for it forever.
struct Publish<'a>(&'a Group);

impl Publish<'_> {
    fn set(self, value: Option<Arc<Shared>>) {
        let mut r = self.0.result.lock().unwrap();
        *r = Some(value);
        self.0.ready.notify_all();
        drop(r);
        std::mem::forget(self);
    }
}

impl Drop for Publish<'_> {
    fn drop(&mut self) {
        let mut r = self.0.result.lock().unwrap_or_else(|e| e.into_inner());
        if r.is_none() {
            *r = Some(None);
        }
        self.0.ready.notify_all();
    }
}

impl Engine {
    /// The rows an earlier search of `query` on this APK left in L3: what
    /// [`Engine::find_refs_with`] replays, so the one-APK and the sweep paths
    /// share results.
    pub fn cached_refs(&self, target: &SearchTarget, query: &Query, aggregate: bool) -> Option<Vec<RefBatch>> {
        let (disk, key) = self.rendered_tier(target)?;
        tiers::decode_batches(&disk.get_rendered(key, &tiers::findrefs_key(query, sweep_opts(aggregate)))?)
    }

    /// Keep the batches of a complete search of `query` on this APK in L3
    /// (not when one failed, see [`Engine::cached_refs`]).
    pub fn store_refs(&self, query: &Query, aggregate: bool, batches: &[RefBatch]) {
        if !self.cache.as_ref().and_then(|c| c.disk.as_deref()).is_some_and(|d| d.uses(Tier::Rendered)) {
            return;
        }
        let Some(apk) = self.open().ok() else { return };
        let Some(key) = self.apk_key(&apk) else { return };
        let mut recorder = tiers::ResultRecorder::new();
        for b in batches {
            recorder.record(b);
        }
        if let Some(payload) = recorder.finish() {
            let query = tiers::findrefs_key(query, sweep_opts(aggregate));
            let job = WriteJob { key, apk: Arc::from(apk.path()), kind: Job::Rendered { query, payload } };
            self.cache.as_ref().expect("an L3 tier implies a cache").put_async(job);
        }
    }

    fn rendered_tier<'a>(&'a self, target: &'a SearchTarget) -> Option<(&'a asc_cache::DiskCache, &'a asc_cache::ApkKey)> {
        let disk = self.cache.as_ref()?.disk.as_deref().filter(|d| d.uses(Tier::Rendered))?;
        Some((disk, target.key.as_ref()?))
    }

    /// [`Engine::search_target_entry`] for an entry claimed in a
    /// [`DexDedup`]: a leading entry is searched and its rows offered to the
    /// entries that follow it; a following one reuses them when its bytes
    /// hash the same.
    pub fn search_target_entry_dedup(
        &self,
        target: &SearchTarget,
        entry: &Entry,
        query: &CompiledQuery,
        aggregate: bool,
        cancel: &AtomicBool,
        claim: &Claim,
    ) -> RefBatch {
        let group = &claim.group;
        if claim.lead {
            let publish = Publish(group);
            let batch = self.search_target_entry(target, entry, query, aggregate, cancel);
            if group.members.load(Ordering::Relaxed) > 1 {
                // The search left the bytes in the memory cache, if there is one.
                let ident = content_id(target, entry, || {
                    self.entry_bytes(&target.apk, target.key.as_ref(), entry).ok().map(|b| Sha256::digest(&**b).into())
                });
                publish.set(ident.map(|ident| Arc::new(Shared { ident, batch: batch.clone() })));
            } else {
                publish.set(None);
            }
            return batch;
        }
        if let Some(shared) = wait_shared(group, cancel) {
            // Hashed once per APK version: later queries of the sweep's
            // session neither read nor inflate a verified follower.
            let ident = content_id(target, entry, || {
                target.apk.read_entry_cancellable(entry, Some(cancel)).ok().map(|b| Sha256::digest(&*b).into())
            });
            if ident == Some(shared.ident) {
                claim.shared.fetch_add(1, Ordering::Relaxed);
                return renamed(shared.batch.clone(), &entry.name);
            }
        }
        self.search_target_entry(target, entry, query, aggregate, cancel)
    }
}

fn sweep_opts(aggregate: bool) -> FindOptions {
    FindOptions { aggregate, context: RefContext::None }
}

/// The leader's result, once it is published.
fn wait_shared(group: &Group, cancel: &AtomicBool) -> Option<Arc<Shared>> {
    let mut r = group.result.lock().unwrap();
    while r.is_none() {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        // The leader is skipped if the sweep is cancelled: poll the flag.
        r = group.ready.wait_timeout(r, Duration::from_millis(50)).unwrap().0;
    }
    r.clone().flatten()
}

/// An entry of one version of an APK file.
type ContentKey = (PathBuf, u64, Option<SystemTime>, String, u32, u64);

/// Most content ids kept; past it the memo starts over.
const MAX_CONTENT_IDS: usize = 1 << 16;

/// `entry`'s SHA-256, from `hash` the first time it is asked for this
/// version of the APK file.
fn content_id(target: &SearchTarget, entry: &Entry, hash: impl FnOnce() -> Option<Ident>) -> Option<Ident> {
    static IDS: OnceLock<Mutex<HashMap<ContentKey, Ident>>> = OnceLock::new();
    let meta = std::fs::metadata(target.apk.path()).ok()?;
    let key = (target.apk.path().to_path_buf(), meta.len(), meta.modified().ok(), entry.name.clone(), entry.crc32, entry.uncomp_size);
    let ids = IDS.get_or_init(Mutex::default);
    if let Some(id) = ids.lock().unwrap().get(&key) {
        return Some(*id);
    }
    let id = hash()?;
    let mut ids = ids.lock().unwrap();
    if ids.len() >= MAX_CONTENT_IDS {
        ids.clear();
    }
    ids.insert(key, id);
    Some(id)
}

/// `batch` as if `name` had produced it: the leader's entry name prefixes
/// the rows' DEX names (`classes2.dex`, `classes2.dex!classes1.dex`).
fn renamed(mut batch: RefBatch, name: &str) -> RefBatch {
    let from = std::mem::replace(&mut batch.entry_name, name.to_string());
    if from != name {
        for r in &mut batch.results {
            if let Some(rest) = r.dex_name.strip_prefix(&from) {
                r.dex_name = format!("{name}{rest}");
            }
        }
        if let Some(e) = &mut batch.error {
            *e = e.replace(&format!("{from}!"), &format!("{name}!"));
        }
    }
    batch.source = "shared";
    batch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RefResult;

    #[test]
    fn renamed_moves_rows_and_container_errors_to_the_follower() {
        let row = |dex: &str| RefResult {
            dex_name: dex.into(),
            method_idx: 0,
            method: "La;->m".into(),
            signature: "La;->m()V".into(),
            matched: vec![],
            relation: None,
            sites: vec![],
            context: None,
        };
        let batch = RefBatch {
            entry_name: "classes2.dex".into(),
            results: vec![row("classes2.dex"), row("classes2.dex!classes1.dex")],
            inflate_us: 0,
            search_us: 0,
            source: "inflate",
            error: Some("classes2.dex!classes2.dex: bad".into()),
        };
        let b = renamed(batch, "classes5.dex");
        assert_eq!(b.entry_name, "classes5.dex");
        assert_eq!(b.results.iter().map(|r| r.dex_name.as_str()).collect::<Vec<_>>(), ["classes5.dex", "classes5.dex!classes1.dex"]);
        assert_eq!(b.error.as_deref(), Some("classes5.dex!classes2.dex: bad"));
        assert_eq!(b.source, "shared");
    }

    #[test]
    fn a_cancelled_or_unwound_leader_releases_followers() {
        let group = Group::default();
        drop(Publish(&group));
        assert!(wait_shared(&group, &AtomicBool::new(false)).is_none());
        let pending = Group::default();
        assert!(wait_shared(&pending, &AtomicBool::new(true)).is_none());
    }
}
