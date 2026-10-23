#!/usr/bin/env python3
"""Signature-filtered findrefs on the prefix-skip path: same rows, and time.

usage: sig_prefix.py DROIDASC TRIALS APK...

For each APK and each query below, runs a one-shot cold CLI search
(`--no-cache`, so Deflate entries go through the prefix probe) and the same
search in an MCP session (its memory cache keeps every entry, so it never
probes). Checks that
  * CLI and MCP give the same rows;
  * the rows of a query with a signature are exactly the rows of the bare
    name narrowed to the targets with that signature (each spelling alike);
and reports the median CLI time and the entries the probe skipped.
"""
import json, os, statistics, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Mcp, text

BIN, TRIALS, APKS = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
ENV = dict(os.environ, DROIDASC_DAEMON="off")

# (bare name, [(spelling, target prefix its rows must have)])
QUERIES = [
    ("Ljava/lang/String;->valueOf", [
        ("Ljava/lang/String;->valueOf(I)Ljava/lang/String;", "Ljava/lang/String;->valueOf(I)Ljava/lang/String;"),
        ("Ljava/lang/String;->valueOf(I)", "Ljava/lang/String;->valueOf(I)"),
        ("java.lang.String.valueOf(int)", "Ljava/lang/String;->valueOf(I)"),
        ("Ljava/lang/String;->valueOf(Ljava/util/UUID;)", "Ljava/lang/String;->valueOf(Ljava/util/UUID;)"),
    ]),
    ("Ljava/lang/StringBuilder;->append", [
        ("Ljava/lang/StringBuilder;->append(Ljava/lang/String;)", "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)"),
        ("java.lang.StringBuilder.append(char)", "Ljava/lang/StringBuilder;->append(C)"),
    ]),
    ("Landroid/telephony/TelephonyManager;->getDeviceId", [
        ("Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;", "Landroid/telephony/TelephonyManager;->getDeviceId()"),
        ("Landroid/telephony/TelephonyManager;->getDeviceId(I)", "Landroid/telephony/TelephonyManager;->getDeviceId(I)"),
    ]),
]


def rows(out):
    return sorted(l for l in out.splitlines() if l and not l.startswith("#"))


def narrow(row, target):
    """`row` of the bare name (one per referencing method, its targets joined
    by ", ") with only the targets that have the signature; None if none do."""
    head, targets = row.rsplit(" | ", 1)
    kept = [t for t in targets.split(", ") if t.startswith(target)]
    return f"{head} | {', '.join(kept)}" if kept else None


def cli(apk, query):
    """Rows, median ms over TRIALS, entries skipped by the probe."""
    times, skipped = [], None
    for _ in range(TRIALS):
        t = time.perf_counter()
        p = subprocess.run([BIN, "--no-cache", "--debug", "findrefs", apk, "method", query], capture_output=True, text=True, env=ENV)
        times.append((time.perf_counter() - t) * 1000)
        for l in p.stderr.splitlines():
            if l.startswith("[DEBUG] Cache:"):
                skipped = int(l.rsplit(",", 1)[1].split()[0])
    return rows(p.stdout), statistics.median(times), skipped


def mcp_rows(m, apk, query):
    r = m.call("findrefs", {"apk": apk, "kind": "method", "value": query, "limit": 1 << 20, "spill": "never", "max_bytes": 1 << 30})
    assert not r.get("isError"), text(r)
    return rows(text(r))


ok = True
# A memory cache keeps every entry, so the session never probes.
m = Mcp([BIN, "--no-cache", "--memory-mb", "4096", "mcp"])
for apk in APKS:
    name = os.path.basename(apk)
    for bare, spellings in QUERIES:
        base, base_ms, base_skip = cli(apk, bare)
        if base != mcp_rows(m, apk, bare):
            ok = False
            print(f"MISMATCH cli/mcp {name} {bare}")
        print(f"{name} | {bare} | {len(base)} rows | {base_ms:.0f} ms | skipped {base_skip}")
        for query, target in spellings:
            got, ms, skip = cli(apk, query)
            want = sorted(filter(None, (narrow(r, target) for r in base)))
            same_mcp = got == mcp_rows(m, apk, query)
            ok &= got == want and same_mcp
            flag = "" if got == want and same_mcp else f" MISMATCH (want {len(want)}, mcp {'same' if same_mcp else 'differs'})"
            print(f"{name} |   {query} | {len(got)} rows | {ms:.0f} ms | skipped {skip}{flag}")
m.close()
print("all consistent" if ok else "INCONSISTENT")
sys.exit(0 if ok else 1)
