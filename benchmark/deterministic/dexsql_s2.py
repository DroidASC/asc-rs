#!/usr/bin/env python3
"""S2 with dexsql CLI: the 8 rules of s2.py as SQL, per (APK, rule) distinct referencing methods.

usage: dexsql_s2.py DEXSQL OUT.json K P T
  K inputs per `dexsql query` (K=1: one process per APK; K>1: one dataset of K APKs, grouped by
  source_path), P processes at a time, each -t T. Corpus as in s2.py ($CORPUS).
"""
import concurrent.futures as cf, json, os, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import TreeSampler, maxrss_mb

X, OUT, K, P, T = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
BASE = os.path.expanduser(os.environ.get("CORPUS_BASE", "~/asc-eval/apks"))
DIRS = [d if d.startswith("/") else os.path.join(BASE, d) for d in os.environ.get("CORPUS", "k80:mi17").split(":")]
APKS = sorted(os.path.join(d, f) for d in DIRS for f in os.listdir(d) if f.endswith(".apk"))
# Same order as s2.py RULES. droidasc string = regex search, method name = substring, class exact.
WHERE = [
    ("method_strings", "value LIKE '%http://%'"),
    ("method_strings", "value LIKE '%password%'"),
    ("method_used_types", "type_descriptor = 'Ldalvik/system/DexClassLoader;'"),
    ("method_calls", "callee_class = 'Ljava/lang/Runtime;' AND callee_name LIKE '%exec%'"),
    ("method_calls", "callee_name LIKE '%addJavascriptInterface%'"),
    ("method_calls", "callee_name LIKE '%setJavaScriptEnabled%'"),
    ("method_calls", "callee_name LIKE '%getDeviceId%'"),
    ("method_calls", "callee_class = 'Ljava/lang/System;' AND callee_name LIKE '%loadLibrary%'"),
]
SQL = " UNION ALL ".join(
    "SELECT %d AS rule, d.source_path AS src, count(DISTINCT t.file_id * 4294967296 + t.method_idx) AS n FROM %s t JOIN dex_files d ON t.file_id = d.file_id WHERE %s GROUP BY d.source_path"
    % (i, tab, w) for i, (tab, w) in enumerate(WHERE))


def apk_id(path):
    return os.path.basename(os.path.dirname(path)) + "/" + os.path.basename(path)[:-4]


batches = [APKS[i:i + K] for i in range(0, len(APKS), K)]
hits, peak, failed = {}, [0], []
lock = threading.Lock()


def run(batch):
    cmd = [X, "query", "-t", T, *[a for p in batch for a in ("-i", p)], "-s", SQL]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    _, _, ru = os.wait4(p.pid, 0) if p.returncode is None else (0, 0, None)
    rows = []
    for l in out.decode("utf-8", "replace").splitlines():
        c = [x.strip() for x in l.strip().strip("|").split("|")]
        if len(c) == 3 and c[0].isdigit():
            rows.append((int(c[0]), c[1], int(c[2])))
    by_src = {}
    for rule, src, n in rows:
        by_src.setdefault(src, {})[str(rule)] = n
    with lock:
        if p.returncode:
            failed.append((len(batch), err.decode()[-160:]))
        for a in batch:
            got = {}
            for src, v in by_src.items():
                if src == a or os.path.realpath(src) == os.path.realpath(a):
                    got = v
            if got:
                hits[apk_id(a)] = got


tree = TreeSampler([os.getpid()])
t = time.perf_counter()
with cf.ThreadPoolExecutor(P) as ex:
    list(ex.map(run, batches))
ms = (time.perf_counter() - t) * 1000
r = dict(mode="dexsql", K=K, P=P, T=int(T), apks=len(APKS), ms=ms, tree_rss_mb=tree.finish(), hits=hits,
         rows=sum(sum(v.values()) for v in hits.values()), failed=len(failed), failed_sample=failed[:3])
json.dump(r, open(OUT, "w"))
print("dexsql K=%-3d P=%-2d T=%-2s %d APKs %8.0f ms  rows %d  tree RSS %d MB  failed batches %d" % (K, P, T, len(APKS), ms, r["rows"], r["tree_rss_mb"], len(failed)))
