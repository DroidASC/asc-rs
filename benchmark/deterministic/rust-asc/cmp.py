#!/usr/bin/env python3
"""Semantic findrefs diff: rust_ASC CLI text vs droidasc MCP JSON.
usage: cmp.py RUST DROIDASC APK  (queries built in)"""
import collections, json, os, re, subprocess, sys
# droidasc forwards one-shot commands to its daemon by default; measure without it unless asked.
os.environ.setdefault("DROIDASC_DAEMON", "off")
RUST, ASC, APK = sys.argv[1:4]
QUERIES = [
    ["string", "http"], ["string", "password"], ["string", "https?://"],
    ["type", "Landroid/webkit/WebView;"], ["type", "Ljava/lang/String;"],
    ["method", "exec", "--class", "java.lang.Runtime"], ["method", "loadUrl"], ["method", "onCreate"],
    ["method", "getDeviceId"], ["method", "addJavascriptInterface"],
    ["field", "SDK_INT"], ["extends", "java.lang.Object"], ["extends", "android.app.Activity"],
    ["impl", "java.lang.Runnable"], ["impl", "android.content.ServiceConnection"],
]
if len(sys.argv) > 4:
    QUERIES = [q for q in QUERIES if q[0] in sys.argv[4:]]
ROW = re.compile(r"^(classes\d*\.dex) \| ")

def rust_rows(q):
    out = subprocess.run([RUST, "findrefs", APK, *q], capture_output=True, text=True, errors="replace").stdout
    recs, cur = [], None
    for line in out.split("\n"):
        if ROW.match(line):
            if cur is not None: recs.append(cur)
            cur = line
        elif cur is not None:
            cur += "\n" + line
    if cur is not None: recs.append(cur.rstrip("\n"))
    rows = collections.Counter()
    for r in recs:
        dex, rest = r.split(" | ", 1)
        if q[0] in ("extends", "impl"):
            m = re.match(r"(\S+) (?:extends|implements) (\S+)$", rest)
            rows[(dex, m.group(1), (m.group(2),))] += 1
            continue
        meth, matched = rest.split(" | matched=(", 1)
        rows[(dex, meth, tuple(sorted(set(matched[:-1].split("; ")))))] += 1
    return rows

def strip(v, kind):
    if kind == "method": return v.split("(")[0]
    if kind == "field": return v.rsplit(":", 1)[0]
    return v

def asc_rows(q):
    args = {"apk": APK, "kind": q[0], "limit": 10**7, "max_bytes": 10**9, "spill": "never"}
    if q[0] in ("string", "type", "extends", "impl"): args["value"] = q[1]
    else:
        args["name"] = q[1]
        if "--class" in q: args["class"] = q[q.index("--class") + 1]
    msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "findrefs", "arguments": args}})
    out = subprocess.run([ASC, "--no-cache", "mcp", "--structured", "full"], input=msg + "\n", capture_output=True, text=True).stdout
    res = json.loads(out.split("\n")[0])["result"]["structuredContent"]["results"]
    rows = collections.Counter()
    for r in res:
        vals = [strip(v, q[0]) for v in r["matched"]]
        # Upstream joins values with "; " and cannot be split back exactly.
        rows[(r["dex"], r["method"], tuple(sorted(set("; ".join(vals).split("; ")))))] += 1
    return rows

bad = 0
for q in QUERIES:
    a, b = rust_rows(q), asc_rows(q)
    na, nb = sum(a.values()), sum(b.values())
    if a == b:
        print(f"ok   {' '.join(q)}: {nb} rows")
        continue
    bad += 1
    only_r, only_a = a - b, b - a
    print(f"DIFF {' '.join(q)}: rust_ASC {na}, asc-rs {nb}; only rust_ASC {sum(only_r.values())}, only asc-rs {sum(only_a.values())}")
    for k in list(only_r)[:2]: print("     rust:", str(k)[:220])
    for k in list(only_a)[:2]: print("     asc :", str(k)[:220])
print(f"{bad} of {len(QUERIES)} queries differ")
