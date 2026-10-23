#!/usr/bin/env python3
"""One `rules` findrefs call vs one findrefs call per rule, over a directory.

usage: rules.py DROIDASC APK_DIR [MODE ...] [-- extra droidasc args]

Modes (default all), each in a fresh `droidasc mcp` process:
  per-rule-seq   one `dir` findrefs per rule, each after the previous reply
  per-rule-par   the same calls sent at once
  rules          a single findrefs with `rules`
Prints wall time, peak RSS of the process, reply bytes and the hits per rule
(which must agree between modes).
"""
import json, os, subprocess, sys, threading, time

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
extra = argv[argv.index("--") + 1:] if "--" in argv else []
argv = argv[:argv.index("--")] if "--" in argv else argv
bin_, apk_dir, modes = argv[0], argv[1], argv[2:] or ["per-rule-seq", "per-rule-par", "rules"]


def peak_rss(pid, stop, out):
    peak = 0
    while not stop.is_set():
        try:
            for l in open(f"/proc/{pid}/status"):
                if l.startswith("VmRSS:"):
                    peak = max(peak, int(l.split()[1]))
        except OSError:
            break
        time.sleep(0.01)
    out.append(peak // 1024)


def session(calls):
    # Per-rule totals live in structuredContent, which the default compact mode trims.
    p = subprocess.Popen([bin_, *extra, "mcp", "--structured", "full"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    stop, peak = threading.Event(), []
    mon = threading.Thread(target=peak_rss, args=(p.pid, stop, peak))
    mon.start()
    t = time.perf_counter()
    replies = []
    for batch in calls:
        for i, args in batch:
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                      "params": {"name": "findrefs", "arguments": args}}) + "\n")
        p.stdin.flush()
        for _ in batch:
            replies.append(json.loads(p.stdout.readline()))
    ms = (time.perf_counter() - t) * 1000
    p.stdin.close(); p.wait()
    stop.set(); mon.join()
    return ms, peak[0], replies


base = {"dir": apk_dir, "max_bytes": 1 << 30, "per_apk": 1000}
for mode in modes:
    if mode == "rules":
        calls = [[(1, {**base, "rules": RULES})]]
    else:
        reqs = [(i + 1, {**base, **r}) for i, r in enumerate(RULES)]
        calls = [[r] for r in reqs] if mode == "per-rule-seq" else [reqs]
    ms, rss, replies = session(calls)
    size = sum(len(r["result"]["content"][0]["text"]) for r in replies)
    if mode == "rules":
        s = replies[0]["result"]["structuredContent"]
        hits = [r["total"] for r in s["rules"]]
    else:
        hits = [r["result"]["structuredContent"]["total"] for r in sorted(replies, key=lambda r: r["id"])]
    print(f"{mode:13s} {len(replies)} calls {ms:7.0f} ms  peak RSS {rss:5d} MB  reply {size // 1024:5d} KiB  hits {hits}")
