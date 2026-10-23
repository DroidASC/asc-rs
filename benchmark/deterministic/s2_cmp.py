#!/usr/bin/env python3
"""usage: s2_cmp.py A.json B.json — per rule: APKs with hits in A only / B only, and APKs whose row counts differ."""
import json, sys
NAMES = ["string http://", "string password", "type DexClassLoader", "method Runtime.exec", "method addJavascriptInterface",
         "method setJavaScriptEnabled", "method getDeviceId", "method System.loadLibrary"]
a, b = (json.load(open(p))["hits"] for p in sys.argv[1:3])
for i, n in enumerate(NAMES):
    k = str(i)
    sa = {x for x, v in a.items() if v.get(k)}
    sb = {x for x, v in b.items() if v.get(k)}
    rows = sum(1 for x in sa & sb if a[x][k] != b[x][k])
    print("%-32s A %3d  B %3d  A-only %-3d B-only %-3d  same-APK row-count diffs %3d   e.g. A-only %s B-only %s" % (
        n, len(sa), len(sb), len(sa - sb), len(sb - sa), rows, sorted(sa - sb)[:2], sorted(sb - sa)[:2]))
