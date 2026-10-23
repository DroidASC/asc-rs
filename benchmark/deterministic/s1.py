#!/usr/bin/env python3
"""Douyin agent-audit replay (47 steps, class_inventory dropped), one process per step (CLI) or one MCP session.

usage: s1.py FLAVOR BIN APK TRIALS OUT.json [global droidasc args...]
  FLAVOR: asc-cli | asc-mcp | asc-mcp-hot | rust-cli | rust-mcp
  asc-mcp      a fresh server per trial (its disk cache as the global args leave it)
  asc-mcp-hot  one server: an untimed pass first, then TRIALS timed passes in the same process
Session ms = whole trial incl. server start; peak RSS = max over step processes (CLI) /
server (asc MCP, wait4) / server tree (rust MCP, ps polling). Scenario order shuffled per trial.
"""
import json, os, random, re, runpy, statistics, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Mcp, TreeSampler, run_measured, text

FLAVOR, BIN, APK, TRIALS, OUT = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
EXTRA = sys.argv[6:]
H = os.environ.get("HARNESS") or os.path.expanduser("~/asc-eval/harness/dexsql-release/benchmarks/agent-audit/harness")
os.environ.update(RASC="RASC", APK=APK, RASC_THREADS="16")
SC = runpy.run_path(os.path.join(H, "rasc_replay.py"), run_name="x")["SCENARIOS"]
SC.pop("class_inventory", None)
BIG = 1 << 30


def to_cli(step):
    cmd, rest = step[1], step[2:]
    cmd = {"manifest": "getmanifest", "classes": "listclass"}.get(cmd, cmd)
    if FLAVOR.startswith("rust"):
        return [BIN, cmd, *["--thread" if x == "--threads" else x for x in rest]]
    return [BIN, *EXTRA, cmd, *rest]


def strip_threads(rest):
    rest = list(rest)
    if "--threads" in rest:
        i = rest.index("--threads")
        del rest[i:i + 2]
    return rest


def to_asc_mcp(step, props):
    cmd, rest = step[1], strip_threads(step[2:])
    apk, rest = rest[0], rest[1:]
    def fit(name, args):
        # Full output in one response, whatever the version's budget / spill defaults are.
        for k, v in (("max_bytes", BIG), ("spill", "never"), ("limit", 1000000), ("full", True), ("debug_info", True)):
            if k in props[name]:
                args[k] = v
        return name, args
    if cmd == "manifest":
        return fit("getmanifest", {"apk": apk})
    if cmd == "getclass":
        return fit("getclass", {"apk": apk, "class": rest[0]})
    kind, val, opts = rest[0], rest[1], rest[2:]
    args = {"apk": apk, "kind": kind}
    args["value" if kind in ("string", "type", "extends", "impl") else "name"] = val
    if "--class" in opts:
        args["class"] = opts[opts.index("--class") + 1]
    return fit("findrefs", args)


def to_rust_mcp(step):
    cmd, rest = step[1], strip_threads(step[2:])
    apk, rest = rest[0], rest[1:]
    if cmd == "manifest":
        return "getmanifest", {"apk_path": apk}
    if cmd == "getclass":
        return "getclass", {"apk_path": apk, "class_name": rest[0]}
    kind, val, opts = rest[0], rest[1], rest[2:]
    q = {"kind": kind}
    q["value" if kind in ("string", "type", "extends", "impl") else "name"] = val
    if "--class" in opts:
        q["class_name"] = opts[opts.index("--class") + 1]
    return "findrefs", {"apk_path": apk, "query": q, "thread": 16}


def names():
    n = list(SC)
    random.shuffle(n)
    return n


def cli_trial():
    t0, peak, outs = time.perf_counter(), 0, {}
    for n in names():
        buf = []
        for s in SC[n]["steps"]:
            out, rss, _ = run_measured(to_cli(s))
            buf.append(out.decode("utf-8", "replace"))
            peak = max(peak, rss)
        outs[n] = buf
    return (time.perf_counter() - t0) * 1000, peak, outs


def mcp_pass(m, props):
    outs = {}
    for n in names():
        outs[n] = [text(m.call(*(to_rust_mcp(s) if FLAVOR == "rust-mcp" else to_asc_mcp(s, props)))) for s in SC[n]["steps"]]
    return outs


def server():
    return [BIN, "mcp"] if FLAVOR == "rust-mcp" else [BIN, *EXTRA, "--threads", "16", "mcp"]


def mcp_trial():
    t0 = time.perf_counter()
    m = Mcp(server())
    tree = TreeSampler([m.p.pid]) if FLAVOR == "rust-mcp" else None
    outs = mcp_pass(m, {} if FLAVOR == "rust-mcp" else m.tool_names())
    ms = (time.perf_counter() - t0) * 1000
    own = m.close()
    return ms, tree.finish() if tree else own, outs


random.seed(1937)
trials = []
if FLAVOR == "asc-mcp-hot":
    m = Mcp(server())
    props = m.tool_names()
    outs = mcp_pass(m, props)
    for _ in range(TRIALS):
        t0 = time.perf_counter()
        outs = mcp_pass(m, props)
        trials.append((time.perf_counter() - t0) * 1000)
    peaks = [m.close()]
else:
    peaks = []
    for _ in range(TRIALS):
        ms, peak, outs = cli_trial() if FLAVOR.endswith("cli") else mcp_trial()
        trials.append(ms)
        peaks.append(peak)

missing = {n: [e for e in SC[n]["expect"] if e not in "\n".join(outs[n])] for n in SC}
missing = {k: v for k, v in missing.items() if v}
res = dict(flavor=FLAVOR, bin=BIN, extra=EXTRA, steps=sum(len(s["steps"]) for s in SC.values()), trials_ms=trials,
           median_ms=statistics.median(trials), peak_rss_mb=max(peaks), missing=missing,
           outputs={n: outs[n] for n in SC})
json.dump(res, open(OUT, "w"))
print("%-12s %-45s %s  %d steps  median %7.0f ms  (min %.0f max %.0f)  peak RSS %d MB  missing %s" % (
    FLAVOR, os.path.basename(BIN), " ".join(EXTRA), res["steps"], res["median_ms"], min(trials), max(trials), res["peak_rss_mb"], missing))
