#!/usr/bin/env python3
"""usage: aggregate.py RESULTS_DIR — medians per config of the s1.py / s2.py result files, as markdown tables.

S1 files are s1-<config>.json (one file, TRIALS inside); every other <config>[.t<k>].json is one
s2.py run, grouped by <config>.
"""
import collections, glob, json, os, re, statistics as st, sys
R = sys.argv[1]
s1 = sorted(glob.glob(os.path.join(R, "s1-*.json")))
if s1:
    print("## S1 (Douyin, 47 steps)\n\n| config | median ms | min-max | peak RSS MB | evidence misses |\n|---|---:|---|---:|---:|")
    for p in s1:
        d = json.load(open(p))
        if "median_ms" not in d:
            continue
        t = d["trials_ms"]
        print("| %s | %.0f | %.0f-%.0f | %d | %d |" % (os.path.basename(p)[3:-5], d["median_ms"], min(t), max(t), d["peak_rss_mb"],
                                                   sum(map(len, d["missing"].values()))))
groups = collections.defaultdict(list)
for p in glob.glob(os.path.join(R, "*.json")):
    name = os.path.basename(p)
    if name.startswith("s1-"):
        continue
    d = json.load(open(p))
    if "ms" in d:
        groups[re.sub(r"(\.t\d+)?\.json$", "", name)].append(d)
if groups:
    print("\n## S2 runs (%s)\n\n| config | trials | median ms | min-max | tree RSS MB (median) | max proc RSS MB | rows |\n|---|---:|---:|---|---:|---:|---:|" % R)
    for k in sorted(groups):
        rs = groups[k]
        ms = [r["ms"] for r in rs]
        print("| %s | %d | %.0f | %.0f-%.0f | %d | %d | %d |" % (k, len(rs), st.median(ms), min(ms), max(ms), st.median(r["tree_rss_mb"] for r in rs),
                                                          max(r.get("proc_rss_mb", 0) for r in rs), rs[0].get("rows", 0)))
