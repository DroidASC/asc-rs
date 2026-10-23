//! Compound queries (one method matching several conditions) and rule sets
//! (several queries answered by one pass over each DEX).
//!
//! Both run their parts through [`FindRefs::find_many`], which merges the
//! located indexes of every part of the same kind and scans the code once
//! per kind, then splits the hits back per part.

use crate::{
    attach_context, matched_name, results_from_hits, rows_compiled, search_entry_with, skip, tiers, Engine, FindOptions, Job, RefBatch,
    RefContext, RefResult, RefSite, RefSummary, Result, SearchTarget, WriteJob,
};
use asc_apk::Entry;
use asc_cache::Tier;
use asc_findrefs::{CompiledQuery, Compound, FindRefs, Query};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;

/// Rows of a compound query ([`Query::All`]) over one DEX: one per method
/// that matches every `all` part and no `none` part. `matched` lists, part
/// by part, the constants each `all` part matched there; the sites are every
/// matching instruction of the `all` parts, in offset order.
pub(crate) fn compound_rows(fr: &FindRefs<'_, '_, '_>, c: &Compound, opts: FindOptions) -> Result<Vec<RefResult>> {
    let dex = fr.dex();
    let parts: Vec<&CompiledQuery> = c.all.iter().chain(&c.none).collect();
    let hits = fr.find_many(&parts)?;
    let n = c.all.len();
    // method -> per `all` part, its (offset, matched index) hits
    let mut methods: BTreeMap<u32, Vec<Vec<(u32, u32)>>> = BTreeMap::new();
    for (p, part_hits) in hits[..n].iter().enumerate() {
        for h in part_hits {
            let Some(ms) = &h.methods else { continue };
            for &m in ms.ids() {
                // The first part proposes the methods, the others can only keep them.
                let slot = if p == 0 { Some(methods.entry(m).or_insert_with(|| vec![Vec::new(); n])) } else { methods.get_mut(&m) };
                if let Some(slot) = slot {
                    slot[p].push((h.offset, h.matched_idx));
                }
            }
        }
    }
    methods.retain(|_, per_part| per_part.iter().all(|h| !h.is_empty()));
    for h in hits[n..].iter().flatten() {
        for &m in h.methods.iter().flat_map(|ms| ms.ids()) {
            methods.remove(&m);
        }
    }
    let mut rows = Vec::with_capacity(methods.len());
    for (m, per_part) in methods {
        let mut matched = Vec::new();
        let mut sites = Vec::new();
        for (part, part_hits) in c.all.iter().zip(per_part) {
            let mut idxs: Vec<u32> = part_hits.iter().map(|&(_, i)| i).collect();
            idxs.sort_unstable();
            idxs.dedup();
            let base = matched.len();
            for &i in &idxs {
                matched.push(matched_name(dex, part.kind(), i)?);
            }
            for (offset, i) in part_hits {
                sites.push(RefSite { offset, matched: base + idxs.binary_search(&i).unwrap_or(0), pc: None, line: None });
            }
        }
        sites.sort_by_key(|s| s.offset);
        rows.push(RefResult::method_row(dex, m, matched, sites)?);
    }
    if opts.context != RefContext::None {
        attach_context(fr, &mut rows, opts.context)?;
    }
    Ok(rows)
}

/// Rows of every rule over one DEX, one list per rule. Plain code queries
/// share [`FindRefs::find_many`]'s scans; class relations and compound
/// queries run on their own.
pub(crate) fn rule_rows(fr: &FindRefs<'_, '_, '_>, rules: &[&CompiledQuery], opts: FindOptions) -> Result<Vec<Vec<RefResult>>> {
    let plain: Vec<usize> = (0..rules.len()).filter(|&i| rules[i].relation().is_none() && rules[i].compound().is_none()).collect();
    let hits = fr.find_many(&plain.iter().map(|&i| rules[i]).collect::<Vec<_>>())?;
    let mut out: Vec<Option<Vec<RefResult>>> = (0..rules.len()).map(|_| None).collect();
    for (&i, hits) in plain.iter().zip(hits) {
        let mut rows = results_from_hits(fr.dex(), rules[i].kind(), &hits, opts.aggregate)?;
        if opts.context != RefContext::None {
            attach_context(fr, &mut rows, opts.context)?;
        }
        out[i] = Some(rows);
    }
    for (i, slot) in out.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(rows_compiled(fr, rules[i], opts)?);
        }
    }
    Ok(out.into_iter().map(Option::unwrap_or_default).collect())
}

/// Compile every rule; the first invalid one fails them all.
pub fn compile_rules(rules: &[Query]) -> Result<Vec<CompiledQuery>> {
    Ok(rules.iter().map(CompiledQuery::new).collect::<std::result::Result<_, _>>()?)
}

impl Engine {
    /// Several queries in one pass: each DEX is loaded once and scanned once
    /// per index kind for all of them. `sink` gets `(rule index, batch)`,
    /// one batch per rule and entry, entries in completion order.
    ///
    /// Each rule shares L3 with [`Engine::find_refs_opts`]: rules an earlier
    /// run left there are replayed, only the others are searched, and each of
    /// those is kept under its own key.
    pub fn find_refs_rules(
        &self,
        rules: &[Query],
        opts: FindOptions,
        cancel: &AtomicBool,
        sink: &mut dyn FnMut(usize, RefBatch),
    ) -> Result<RefSummary> {
        let t0 = Instant::now();
        let _query = self.prebuild.query();
        let compiled = compile_rules(rules)?;
        let apk = self.open()?;
        let mut entries = apk.dex_entries()?;
        // Largest first, as in `find_refs_opts`.
        entries.reverse();
        let key = self.apk_key(&apk);
        let mut summary = RefSummary { entries: entries.len(), ..Default::default() };
        if entries.is_empty() || compiled.is_empty() {
            return Ok(summary);
        }
        let disk = self.cache.as_ref().and_then(|c| c.disk.as_deref()).filter(|d| d.uses(Tier::Rendered));
        let rendered = disk.zip(key.as_ref());
        let mut missing = Vec::new();
        for (i, rule) in rules.iter().enumerate() {
            let replay =
                rendered.and_then(|(d, k)| d.get_rendered(k, &tiers::findrefs_key(rule, opts))).and_then(|b| tiers::decode_batches(&b));
            match replay {
                Some(batches) => {
                    for batch in batches {
                        summary.total_results += batch.results.len();
                        sink(i, batch);
                    }
                }
                None => missing.push(i),
            }
        }
        if missing.is_empty() {
            summary.total_us = t0.elapsed().as_micros();
            self.log(format!("[APK] for_each_findrefs_rules total={} us rules={} source=result", summary.total_us, rules.len()));
            return Ok(summary);
        }
        let mut recorders: Vec<_> = missing.iter().map(|_| rendered.map(|_| tiers::ResultRecorder::new())).collect();
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<Vec<RefBatch>>();
        let workers = self.threads().min(entries.len()).max(1);
        let searched: Vec<&CompiledQuery> = missing.iter().map(|&i| &compiled[i]).collect();
        let (cache, stats, searched) = (self.cache.as_deref(), &self.stats, &searched);
        let run = |fr: &FindRefs<'_, '_, '_>| rule_rows(fr, searched, opts);
        // An entry is left out only when no rule can match it.
        let probe = skip::Probe::new(searched.clone());
        let probe = &probe;
        std::thread::scope(|s| {
            for _ in 0..workers {
                let tx = tx.clone();
                let (apk, entries, next, key, run) = (&apk, &entries, &next, key.as_ref(), &run);
                s.spawn(move || loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    let batches = search_entry_with(apk, key, entry, searched.len(), run, Some(probe), cancel, cache, stats);
                    if tx.send(batches).is_err() {
                        break;
                    }
                });
            }
            drop(tx);
            for batches in rx {
                for (j, batch) in batches.into_iter().enumerate() {
                    summary.total_results += batch.results.len();
                    if let Some(r) = recorders[j].as_mut() {
                        r.record(&batch);
                    }
                    sink(missing[j], batch);
                }
            }
        });
        // A cancelled run may be missing entries.
        if let Some((_, k)) = rendered.filter(|_| !cancel.load(Ordering::Relaxed)) {
            for (&i, recorder) in missing.iter().zip(recorders) {
                if let Some(payload) = recorder.and_then(tiers::ResultRecorder::finish) {
                    let query = tiers::findrefs_key(&rules[i], opts);
                    let job = WriteJob { key: k.clone(), apk: Arc::from(apk.path()), kind: Job::Rendered { query, payload } };
                    self.cache.as_ref().expect("rendered implies a cache").put_async(job);
                }
            }
        }
        summary.total_us = t0.elapsed().as_micros();
        self.log(format!(
            "[APK] for_each_findrefs_rules total={} us count={} rules={} searched={} workers={workers}",
            summary.total_us,
            entries.len(),
            rules.len(),
            missing.len()
        ));
        Ok(summary)
    }

    /// [`Engine::search_target_entry`] for a rule set: one batch per rule.
    pub fn search_target_entry_rules(
        &self,
        target: &SearchTarget,
        entry: &Entry,
        rules: &[&CompiledQuery],
        aggregate: bool,
        cancel: &AtomicBool,
    ) -> Vec<RefBatch> {
        let opts = FindOptions { aggregate, context: RefContext::None };
        let run = |fr: &FindRefs<'_, '_, '_>| rule_rows(fr, rules, opts);
        search_entry_with(&target.apk, target.key.as_ref(), entry, rules.len(), &run, None, cancel, self.cache.as_deref(), &self.stats)
    }
}
