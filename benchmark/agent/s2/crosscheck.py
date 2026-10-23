#!/usr/bin/env python3
"""usage: crosscheck.py DEXSQL APK_DIR REF.json — recompute each goal with dexsql method_calls, diff against REF."""
import concurrent.futures as cf, json, os, runpy, subprocess, sys
X, D, REF = sys.argv[1:4]
GOALS = runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "goals.py"))["GOALS"]
ref = json.load(open(REF))
def cond(rule):
    cls, name = rule[len("method:"):].split("->")
    return "(callee_class = 'L%s;' AND callee_name = '%s')" % (cls.replace(".", "/"), name)
sql = "SELECT %s FROM method_calls" % ", ".join(
    "sum(CASE WHEN %s THEN 1 ELSE 0 END) AS %s" % (" OR ".join(map(cond, s["rules"])), g) for g, s in GOALS.items())
def one(a):
    r = subprocess.run([X, "query", "-t", "2", "-i", os.path.join(D, a), "-s", sql], capture_output=True, text=True)
    nums = [w for w in r.stdout.replace("|", " ").split() if w.isdigit() or w == "NULL"]
    return a[:-4], nums[-len(GOALS):] if len(nums) >= len(GOALS) else None, r.stderr[-200:]
apks = sorted(f for f in os.listdir(D) if f.endswith(".apk"))
got = {g: set() for g in GOALS}; bad = []
with cf.ThreadPoolExecutor(16) as ex:
    for stem, nums, err in ex.map(one, apks):
        if nums is None: bad.append((stem, err)); continue
        for g, n in zip(GOALS, nums):
            if n not in ("0", "NULL"): got[g].add(stem)
for g in GOALS:
    r = set(ref[g]); print(g, "ref", len(r), "dexsql", len(got[g]), "only-ref", sorted(r - got[g]), "only-dexsql", sorted(got[g] - r))
print("dexsql failed:", len(bad), bad[:3])
