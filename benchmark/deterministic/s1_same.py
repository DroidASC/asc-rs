#!/usr/bin/env python3
"""usage: s1_same.py NEW.json OLD.json [OTHER.json...] — findrefs rows of new vs old as (dex, method) multisets, getclass texts, evidence misses."""
import collections, json, sys
new, old = (json.load(open(p)) for p in sys.argv[1:3])
others = [json.load(open(p)) for p in sys.argv[3:]]

def rows(t):
    # new: `dex | Lc;->m(sig)R | hits`, old: `dex | Lc;->m | matched=(...)`
    out = collections.Counter()
    for l in t.splitlines():
        parts = l.split(" | ")
        if len(parts) >= 3 and parts[0].endswith(".dex"):
            out[(parts[0], parts[1].split("(")[0])] += 1
    return out

same = diff = gsame = gdiff = 0
for n in new["outputs"]:
    for a, b in zip(new["outputs"][n], old["outputs"][n]):
        if a.startswith(".class") or b.startswith(".class"):
            if a == b: gsame += 1
            else: gdiff += 1
        elif rows(a) == rows(b):
            same += 1
        else:
            diff += 1
            print("DIFF", n, sorted((rows(a) - rows(b)).items())[:3], sorted((rows(b) - rows(a)).items())[:3])
print("findrefs/manifest steps same %d differ %d; getclass identical %d differ %d" % (same, diff, gsame, gdiff))
for r in [new, old] + others:
    print(r["flavor"], r["bin"].split("/")[-1], " ".join(r["extra"]), "misses", sum(map(len, r["missing"].values())), sorted(r["missing"].items()) == sorted(new["missing"].items()))
