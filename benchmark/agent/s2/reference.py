#!/usr/bin/env python3
"""usage: reference.py DROIDASC APK_DIR OUT.json — per goal, the APK stems with a hit."""
import concurrent.futures as cf, json, os, runpy, subprocess, sys
B, D, OUT = sys.argv[1:4]
GOALS = runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "goals.py"))["GOALS"]
apks = sorted(f for f in os.listdir(D) if f.endswith(".apk"))

def one(apk):
    hits = {}
    for g, spec in GOALS.items():
        r = subprocess.run([B, "--no-cache", "findrefs", os.path.join(D, apk), "rules", *spec["rules"], "--threads", "2"],
                           capture_output=True, text=True)
        rows = [l for l in r.stdout.splitlines() if l and not l.startswith("#")]
        hits[g] = len(rows)
    return apk[:-4], hits

ref = {g: {} for g in GOALS}
with cf.ThreadPoolExecutor(16) as ex:
    for stem, hits in ex.map(one, apks):
        for g, n in hits.items():
            if n:
                ref[g][stem] = n
json.dump(ref, open(OUT, "w"), indent=1, sort_keys=True)
for g, m in ref.items():
    print(g, len(m))
