#!/usr/bin/env python3
"""prefix-skip (round 2): cold one-shot findrefs: median wall ms and peak RSS over N runs, per binary.

usage: ps_bench.py APK N BIN... -- QUERY ARGS ; QUERY ARGS ; ...
"""
import os, statistics, subprocess, sys, time
# droidasc forwards one-shot commands to its daemon by default; measure without it unless asked.
os.environ.setdefault("DROIDASC_DAEMON", "off")

apk, n = sys.argv[1], int(sys.argv[2])
rest = sys.argv[3:]
bins = rest[: rest.index("--")]
queries = [q.split() for q in " ".join(rest[rest.index("--") + 1 :]).split(" ; ")]


def run(b, q):
    ts, rss = [], 0
    for _ in range(n):
        t = time.perf_counter()
        p = subprocess.Popen([b, "--no-cache", "findrefs", apk, *q], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _, _, ru = os.wait4(p.pid, 0)
        ts.append((time.perf_counter() - t) * 1e3)
        rss = max(rss, ru.ru_maxrss // (1 << 20) if sys.platform == "darwin" else ru.ru_maxrss // 1024)
    return statistics.median(ts), rss


for q in queries:
    cells = []
    for b in bins:
        ms, rss = run(b, q)
        cells.append(f"{ms:6.0f} ms {rss:5} MB")
    print(f"{' '.join(q)[:48]:48} " + " | ".join(cells))
