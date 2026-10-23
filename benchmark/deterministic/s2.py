#!/usr/bin/env python3
"""S2 multi-APK audit: every APK of the corpus dirs x 8 rules.

usage: s2.py MODE BIN OUT.json ARGS... [-- global droidasc args...]
  cli P T        pool of P one-shot `findrefs` processes (one per APK x rule), each --threads T
  mcp N          N concurrent `mcp` servers, APKs split between them by size; each runs one
                 multi-APK `findrefs dir=<its slice>` per rule (all cursor pages)
  clirules P T   pool of P one-shot `findrefs APK rules` processes (one per APK, all 8 rules in one pass)
  mcprules N     as mcp, but one multi-APK `findrefs rules=[...]` per slice (each APK loaded once)
  rust P T       pool of P rust_ASC `findrefs` processes
Corpus: $CORPUS (colon-separated dirs, relative ones under $CORPUS_BASE, default k80:mi17 under ~/asc-eval/apks).
Peak RSS: `tree` = peak over time of the summed RSS of every process (ps polling, 50 ms);
`proc` = max single-process RSS (wait4).
"""
import concurrent.futures as cf, json, os, re, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Mcp, TreeSampler, maxrss_mb

RULES = [
    {"kind": "string", "value": "http://"},
    {"kind": "string", "value": "password"},
    {"kind": "type", "value": "Ldalvik/system/DexClassLoader;"},
    {"kind": "method", "name": "exec", "class": "java.lang.Runtime"},
    {"kind": "method", "name": "addJavascriptInterface"},
    {"kind": "method", "name": "setJavaScriptEnabled"},
    {"kind": "method", "name": "getDeviceId"},
    {"kind": "method", "name": "loadLibrary", "class": "java.lang.System"},
]
argv = sys.argv[1:]
EXTRA = argv[argv.index("--") + 1:] if "--" in argv else []
argv = argv[:argv.index("--")] if "--" in argv else argv
MODE, BIN, OUT, ARGS = argv[0], argv[1], argv[2], argv[3:]
BASE = os.path.expanduser(os.environ.get("CORPUS_BASE", "~/asc-eval/apks"))
DIRS = [d if d.startswith("/") else os.path.join(BASE, d) for d in os.environ.get("CORPUS", "k80:mi17").split(":")]
APKS = sorted(os.path.join(d, f) for d in DIRS for f in os.listdir(d) if f.endswith(".apk"))
BIG = 1 << 30


def apk_id(path):
    return os.path.basename(os.path.dirname(path)) + "/" + os.path.basename(path)[:-4]


def cli_args(rule):
    if rule["kind"] in ("string", "type"):
        return [rule["kind"], rule["value"]]
    return ["method", rule["name"]] + (["--class", rule["class"]] if "class" in rule else [])


def rule_spec(rule):
    if rule["kind"] in ("string", "type"):
        return "%s:%s" % (rule["kind"], rule["value"])
    return "method:" + ("%s->%s" % (rule["class"], rule["name"]) if "class" in rule else rule["name"])


ROW = re.compile(rb"^(?:r(\d+) \| )?(?:classes\d*\.dex|[^ |]+\.dex) \| ")


def pool(P, cmd_of, per_apk=False):
    jobs = [(a, None) for a in APKS] if per_apk else [(a, i) for a in APKS for i in range(len(RULES))]
    hits, peak = {}, [0]
    lock = threading.Lock()

    def run(job):
        a, i = job
        p = subprocess.Popen(cmd_of(a, None if i is None else RULES[i]), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out = p.stdout.read()
        _, _, ru = os.wait4(p.pid, 0)
        counts = {}
        for l in out.splitlines():
            m = ROW.match(l)
            if m:
                k = str(int(m.group(1)) - 1) if m.group(1) else str(i)
                counts[k] = counts.get(k, 0) + 1
        with lock:
            peak[0] = max(peak[0], maxrss_mb(ru))
            if counts:
                hits.setdefault(apk_id(a), {}).update(counts)

    tree = TreeSampler([os.getpid()])
    t = time.perf_counter()
    with cf.ThreadPoolExecutor(P) as ex:
        list(ex.map(run, jobs))
    ms = (time.perf_counter() - t) * 1000
    return dict(ms=ms, procs=len(jobs), proc_rss_mb=peak[0], tree_rss_mb=tree.finish(), hits=hits,
                rows=sum(sum(v.values()) for v in hits.values()))


def slices(n):
    root = os.path.join(os.environ.get("SLICES", os.path.join(os.environ.get("BENCH_TMP", "/private/tmp/asc-bench"), "slices")), "n%d" % n)
    by_size = sorted(APKS, key=os.path.getsize, reverse=True)
    out = []
    for k in range(n):
        d = os.path.join(root, str(k))
        os.makedirs(d, exist_ok=True)
        for f in os.listdir(d):
            os.unlink(os.path.join(d, f))
        for a in by_size[k::n]:
            os.symlink(a, os.path.join(d, apk_id(a).replace("/", "-") + ".apk"))
        out.append(d)
    return out


def mcp(n, rules=False):
    dirs = slices(n)
    threads = os.environ.get("THREADS") or str(max(2, (os.cpu_count() or 32) // n))
    # AUTO=1: no --threads, the binary's own default (threads reported as 0).
    auto = os.environ.get("AUTO") == "1"
    servers = [Mcp([BIN, *EXTRA, *([] if auto else ["--threads", threads]), "mcp"]) for _ in range(n)]
    threads = "0" if auto else threads
    props = servers[0].tool_names()["findrefs"]
    tree = TreeSampler([s.p.pid for s in servers])
    res = [None] * n

    def drive(k):
        m, total, calls, errors = servers[k], 0, 0, 0
        for rule in [{"rules": RULES}] if rules else RULES:
            args = dict(rule, dir=dirs[k])
            for key, v in (("limit", 1000000), ("max_bytes", BIG), ("spill", "never"), ("collapse_sdks", False)):
                if key in props:
                    args[key] = v
            while True:
                r = m.call("findrefs", args)
                calls += 1
                errors += bool(r.get("isError"))
                sc = r.get("structuredContent") or {}
                total += sc.get("total", 0)
                if not sc.get("cursor"):
                    break
                args = {"cursor": sc["cursor"]}
        res[k] = (total, calls, errors)

    t = time.perf_counter()
    ths = [threading.Thread(target=drive, args=(k,)) for k in range(n)]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    ms = (time.perf_counter() - t) * 1000
    own = [s.close() for s in servers]
    return dict(ms=ms, servers=n, threads=int(threads), tree_rss_mb=tree.finish(), proc_rss_mb=max(own), sum_proc_rss_mb=sum(own),
                rows=sum(r[0] for r in res), calls=sum(r[1] for r in res), errors=sum(r[2] for r in res))


if MODE == "cli":
    P, T = int(ARGS[0]), ARGS[1]
    r = pool(P, lambda a, rule: [BIN, *EXTRA, "--threads", T, "findrefs", a, *cli_args(rule)])
elif MODE == "clirules":
    P, T = int(ARGS[0]), ARGS[1]
    r = pool(P, lambda a, _: [BIN, *EXTRA, "--threads", T, "findrefs", a, "rules", *map(rule_spec, RULES)], per_apk=True)
elif MODE == "rust":
    P, T = int(ARGS[0]), ARGS[1]
    r = pool(P, lambda a, rule: [BIN, "findrefs", "--thread", T, a, *cli_args(rule)])
else:
    r = mcp(int(ARGS[0]), rules=MODE == "mcprules")
r.update(mode=MODE, bin=BIN, args=ARGS, extra=EXTRA, apks=len(APKS))
json.dump(r, open(OUT, "w"))
print("%-4s %-12s %-6s %-40s %d APKs %8.0f ms  rows %d  tree RSS %d MB  proc RSS %d MB%s" % (
    MODE, os.path.basename(BIN), " ".join(ARGS), " ".join(EXTRA)[-40:], len(APKS), r["ms"], r["rows"], r["tree_rss_mb"], r["proc_rss_mb"],
    "  calls %d errors %d" % (r["calls"], r["errors"]) if MODE.startswith("mcp") else ""))
