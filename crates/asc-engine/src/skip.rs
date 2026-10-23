//! Skipping DEX entries a search cannot match, decided from a streamed
//! prefix ([`Probe`]).
//!
//! A reference search locates its targets in the id tables and the string
//! data before it reads any code. Where a DEX keeps its string data near the
//! front (Douyin's do, in the first third), inflating that prefix is enough
//! to see that a query locates nothing, and the rest of the entry is never
//! inflated. The answer is the one the full search gives: the same locators
//! run on the same bytes, and anything they cannot read from the prefix
//! sends the entry down the normal path.
//!
//! The prefix goes through a streaming decoder, about 1.6x slower per byte
//! than the one-shot decoder of a full inflate, and is thrown away when the
//! DEX turns out to match. So a probe is only worth it:
//!
//! * for a Deflate entry no cache will keep: with a memory cache or an L1
//!   that admits the entry, inflating it once serves every later query;
//! * when the string data ends within [`WORTH_BELOW`] of the entry;
//! * while most probes of this search skip: after [`WARMUP`] probes, probing
//!   stops once more than half of them found the DEX could match.

use crate::{EngineCache, Stats};
use asc_apk::{Apk, Entry, Prefix, PrefixStep};
use asc_cache::Tier;
use asc_dex::Dex;
use asc_findrefs::{CompiledQuery, FindRefs};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Entries below this are cheaper to inflate whole than to probe.
const MIN_GAIN: u64 = 256 * 1024;
/// Room after the last string offset for that string's own bytes.
const SLACK: usize = 64 * 1024;
/// Largest share of the entry a probe may inflate: past it, streaming the
/// prefix costs about as much as the one-shot inflate it would save.
const WORTH_BELOW: f64 = 0.45;
/// Probes run before their skip rate decides whether to go on.
const WARMUP: usize = 4;

/// The queries of one search over an APK, and how its probes went so far.
pub(crate) struct Probe<'q> {
    queries: Vec<&'q CompiledQuery>,
    started: AtomicUsize,
    probed: AtomicUsize,
    matched: AtomicUsize,
}

impl<'q> Probe<'q> {
    pub(crate) fn new(queries: Vec<&'q CompiledQuery>) -> Probe<'q> {
        Probe { queries, started: AtomicUsize::new(0), probed: AtomicUsize::new(0), matched: AtomicUsize::new(0) }
    }

    /// Whether `entry` can be left out of the search: none of the queries
    /// can match it. `false` also when a probe is not worth it or cannot tell.
    pub(crate) fn skips(&self, apk: &Apk, entry: &Entry, cache: Option<&EngineCache>, stats: &Stats) -> bool {
        if !worth_a_prefix(entry, cache) || !self.admit() {
            return false;
        }
        let skip = self.cannot_match(apk, entry);
        self.probed.fetch_add(1, Ordering::Relaxed);
        if skip {
            stats.skipped.fetch_add(1, Ordering::Relaxed);
        } else {
            self.matched.fetch_add(1, Ordering::Relaxed);
        }
        skip
    }

    /// The first [`WARMUP`] entries are probed; later ones while at most half
    /// of the probes so far found a possible match.
    fn admit(&self) -> bool {
        let probed = self.probed.load(Ordering::Relaxed);
        if probed < WARMUP {
            return self.started.fetch_add(1, Ordering::Relaxed) < WARMUP;
        }
        self.matched.load(Ordering::Relaxed) * 2 <= probed
    }

    fn cannot_match(&self, apk: &Apk, entry: &Entry) -> bool {
        let Some(bytes) = id_prefix(apk, entry) else { return false };
        let Ok(dex) = Dex::with_name(&bytes, &entry.name) else { return false };
        let fr = FindRefs::new(&dex);
        // An error is a prefix too short for the answer, or a damaged DEX the
        // full search reports itself.
        self.queries.iter().all(|q| fr.cannot_match(q).unwrap_or(false))
    }
}

/// Whether reading `entry`'s id tables from a streamed prefix
/// ([`id_prefix`]) can beat inflating it: a Deflate entry large enough that
/// no cache will keep once inflated.
pub(crate) fn worth_a_prefix(entry: &Entry, cache: Option<&EngineCache>) -> bool {
    entry.method == asc_apk::METHOD_DEFLATE && entry.uncomp_size > MIN_GAIN && !kept(cache, entry)
}

/// The leading bytes of `entry` through its id tables and string data,
/// streamed, when they end within [`WORTH_BELOW`] of it; `None` otherwise
/// (also for what is not a single plain DEX). A [`Dex`] over them answers
/// what the id tables and strings hold and fails on anything past them.
pub(crate) fn id_prefix(apk: &Apk, entry: &Entry) -> Option<Vec<u8>> {
    let size = entry.uncomp_size as usize;
    let budget = (size as f64 * WORTH_BELOW) as usize;
    let prefix = apk.inflate_until(entry, |out| {
        if out.len() >= 8 && (&out[..4] != b"dex\n" || &out[..8] == asc_dex::container::DEX041_MAGIC) {
            return PrefixStep::Abort;
        }
        // The usual d8 / R8 layout puts the string data near the end: a
        // first few strings already past the budget settle it at once.
        if asc_dex::quick::leading_string_data_off(out).is_some_and(|off| off > budget) {
            return PrefixStep::Abort;
        }
        match asc_dex::quick::id_tables_needed_len(out) {
            Some(needed) if needed + SLACK <= budget => PrefixStep::Continue(needed + SLACK),
            Some(_) => PrefixStep::Abort,
            None if out.len() > budget => PrefixStep::Abort,
            None => PrefixStep::Continue(0),
        }
    });
    match prefix {
        Ok(Prefix::Partial(b) | Prefix::Complete(b)) => Some(b),
        Ok(Prefix::Aborted(_)) | Err(_) => None,
    }
}

/// Whether a cache keeps `entry` once inflated, so later queries reuse it.
fn kept(cache: Option<&EngineCache>, entry: &Entry) -> bool {
    cache.is_some_and(|c| c.memory.is_some() || c.disk.as_ref().is_some_and(|d| d.uses(Tier::Dex) && d.admits_dex(entry.uncomp_size)))
}
