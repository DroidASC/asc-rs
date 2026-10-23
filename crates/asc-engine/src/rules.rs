//! Compound queries (one method matching several conditions) and rule sets
//! (several queries answered by one pass over each DEX).
//!
//! Both run their parts through [`FindRefs::find_many`], which merges the
//! located indexes of every part of the same kind and scans the code once
//! per kind, then splits the hits back per part.

use crate::{
    attach_context, hit_matched, results_from_hits, rows_compiled, search_entry_with, skip, tiers, Engine, FindOptions, Job, RefBatch,
    RefContext, RefResult, RefSite, RefSummary, Result, SearchTarget, WriteJob,
};
use asc_apk::Entry;
use asc_cache::Tier;
use asc_findrefs::{CompiledQuery, Compound, Defined, FindRefs, Query};
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
    // Code parts are found with a shared scan; definition parts (`flag:`,
    // `override:`, ...) name methods from the class definitions instead.
    let code_all: Vec<&CompiledQuery> = c.all.iter().filter(|q| q.defined().is_none()).collect();
    let code_none: Vec<&CompiledQuery> = c.none.iter().filter(|q| q.defined().is_none()).collect();
    let def_all: Vec<&Defined> = c.all.iter().filter_map(|q| q.defined()).collect();
    let def_none: Vec<&Defined> = c.none.iter().filter_map(|q| q.defined()).collect();

    let parts: Vec<&CompiledQuery> = code_all.iter().chain(&code_none).copied().collect();
    let hits = fr.find_many(&parts)?;
    let n = code_all.len();
    // method -> per code `all` part, its (offset, matched index, note) hits
    type PartHits<'h> = Vec<(u32, u32, Option<&'h str>)>;
    let mut methods: BTreeMap<u32, Vec<PartHits<'_>>> = BTreeMap::new();
    if n == 0 {
        // No code part proposes methods: seed from the first definition part.
        let seed = defined_method_set(dex, def_all[0])?;
        for m in seed {
            methods.insert(m, Vec::new());
        }
    } else {
        for (p, part_hits) in hits[..n].iter().enumerate() {
            for h in part_hits {
                let Some(ms) = &h.methods else { continue };
                for &m in ms.ids() {
                    // The first part proposes the methods, the others can only keep them.
                    let slot = if p == 0 { Some(methods.entry(m).or_insert_with(|| vec![Vec::new(); n])) } else { methods.get_mut(&m) };
                    if let Some(slot) = slot {
                        slot[p].push((h.offset, h.matched_idx, h.note.as_deref()));
                    }
                }
            }
        }
        methods.retain(|_, per_part| per_part.iter().all(|h| !h.is_empty()));
    }
    // Keep only methods every definition `all` part also names (`def_all[0]`
    // already seeded the set when there is no code part).
    for d in def_all.iter().skip(usize::from(n == 0)) {
        let keep = defined_method_set(dex, d)?;
        methods.retain(|m, _| keep.contains(m));
    }
    // Drop methods a `none` part matches, code or definition.
    for h in hits[n..].iter().flatten() {
        for &m in h.methods.iter().flat_map(|ms| ms.ids()) {
            methods.remove(&m);
        }
    }
    for d in &def_none {
        let drop = defined_method_set(dex, d)?;
        methods.retain(|m, _| !drop.contains(m));
    }
    let def_labels: Vec<String> = def_all.iter().map(|d| d.label()).collect();
    let mut rows = Vec::with_capacity(methods.len());
    for (m, per_part) in methods {
        let mut matched = Vec::new();
        let mut sites = Vec::new();
        for (part, part_hits) in code_all.iter().zip(per_part) {
            let mut idxs: Vec<(u32, Option<&str>)> = part_hits.iter().map(|&(_, i, note)| (i, note)).collect();
            idxs.sort_unstable();
            idxs.dedup();
            let base = matched.len();
            for &(i, note) in &idxs {
                matched.push(hit_matched(dex, part.kind(), i, note)?);
            }
            for (offset, i, note) in part_hits {
                sites.push(RefSite { offset, matched: base + idxs.binary_search(&(i, note)).unwrap_or(0), pc: None, line: None });
            }
        }
        for label in &def_labels {
            matched.push(crate::Matched::Symbol(label.clone()));
        }
        sites.sort_by_key(|s| s.offset);
        rows.push(RefResult::method_row(dex, m, matched, sites)?);
    }
    if opts.context != RefContext::None {
        attach_context(fr, &mut rows, opts.context)?;
    }
    Ok(rows)
}

/// The method ids a resolved definition predicate names in this DEX, as a set.
fn defined_method_set(dex: &asc_dex::Dex<'_>, d: &Defined) -> Result<std::collections::BTreeSet<u32>> {
    Ok(crate::defs::defined_methods(dex, d)?.into_iter().collect())
}

/// Rows of every rule over one DEX, one list per rule. Plain code queries
/// share [`FindRefs::find_many`]'s scans; class relations and compound
/// queries run on their own.
pub(crate) fn rule_rows(fr: &FindRefs<'_, '_, '_>, rules: &[&CompiledQuery], opts: FindOptions) -> Result<Vec<Vec<RefResult>>> {
    let plain: Vec<usize> = (0..rules.len())
        .filter(|&i| rules[i].relation().is_none() && rules[i].compound().is_none() && rules[i].defined().is_none())
        .collect();
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
        for rule in rules {
            crate::compose::check_patterns(rule)?;
        }
        if let Some(engine) = self.transient(rules.iter().any(crate::compose::needs_program))? {
            return engine.find_refs_rules(rules, opts, cancel, sink);
        }
        let apk = self.open()?;
        let mut entries = apk.dex_entries()?;
        // Largest first, as in `find_refs_opts`.
        entries.reverse();
        let key = self.apk_key(&apk);
        let mut summary = RefSummary { entries: entries.len(), ..Default::default() };
        if entries.is_empty() || rules.is_empty() {
            return Ok(summary);
        }
        let disk = self.cache.as_ref().and_then(|c| c.disk.as_deref()).filter(|d| d.uses(Tier::Rendered));
        let rendered = disk.zip(key.as_ref());
        let mut missing = Vec::new();
        for (i, rule) in rules.iter().enumerate() {
            let replay =
                rendered.and_then(|(d, k)| d.get_rendered(k, &tiers::findrefs_key(rule, opts))).and_then(|b| tiers::decode_batches(&b));
            match replay {
                Some(recorded) => {
                    for batch in recorded.batches {
                        summary.total_results += batch.results.len();
                        sink(i, batch);
                    }
                    summary.notes.extend(recorded.notes);
                }
                None => missing.push(i),
            }
        }
        if missing.is_empty() {
            summary.notes = crate::compose::merge_notes(std::mem::take(&mut summary.notes));
            summary.total_us = t0.elapsed().as_micros();
            self.log(format!("[APK] for_each_findrefs_rules total={} us rules={} source=result", summary.total_us, rules.len()));
            return Ok(summary);
        }
        // The `method:{RULE}` conditions of the rules to search, all in one
        // pass first. L3 keys on the rules as given, so replays skip this.
        let todo: Vec<Query> = missing.iter().map(|&i| rules[i].clone()).collect();
        let resolved = self.resolve(&todo, cancel)?;
        let rule_notes = resolved.notes;
        summary.notes.extend(rule_notes.iter().flatten().cloned());
        summary.notes = crate::compose::merge_notes(std::mem::take(&mut summary.notes));
        let _query = self.prebuild.query();
        let compiled = compile_rules(resolved.queries.as_deref().unwrap_or(&todo))?;
        let mut recorders: Vec<_> = missing.iter().map(|_| rendered.map(|_| tiers::ResultRecorder::new())).collect();
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<Vec<RefBatch>>();
        let workers = self.threads().min(entries.len()).max(1);
        let searched: Vec<&CompiledQuery> = compiled.iter().collect();
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
            for ((&i, recorder), notes) in missing.iter().zip(recorders).zip(&rule_notes) {
                if let Some(payload) = recorder.and_then(|r| r.finish(notes)) {
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
