#!/usr/bin/env python3
"""usage: score.py ROOT TAG REF.json — per run: recall / precision of the `APK:` lines, tokens, cost, wall."""
import glob, json, os, re, statistics as st, sys, collections
ROOT, TAG, REF = sys.argv[1:4]
ref = json.load(open(REF))
rows = collections.defaultdict(list)
for p in sorted(glob.glob(os.path.join(ROOT, "runs", TAG, "*.ndjson"))):
    tool, name, rep = os.path.basename(p)[:-len(".ndjson")].rsplit(".", 2)
    ev = [json.loads(l) for l in open(p) if l.strip()]
    end = next((e for e in ev if e.get("type") == "end"), {})
    answer = "".join(e["data"] for e in ev if e.get("type") == "text" and isinstance(e.get("data"), str))
    said = {m.strip(" `*") for m in re.findall(r"APK:\s*`?([A-Za-z0-9_.]+)", answer)}
    said = {s[:-4] if s.endswith(".apk") else s for s in said}
    req, opt = set(ref[name]["required"]), set(ref[name]["optional"])
    tp, fp = len(said & req), len(said - req - opt)
    calls = [e for e in ev if e.get("type") == "tool_call"]
    u = end.get("usage", {})
    rows[tool].append(dict(name=name, rep=rep, recall=tp / len(req), prec=tp / max(1, tp + fp), fp=fp, calls=len(calls),
                           tokens=u.get("total_tokens", 0), cost=end.get("total_cost_usd", 0),
                           wall=next((e["seconds"] for e in ev if e.get("type") == "wall"), 0), ok=end.get("stopReason") == "end_turn",
                           missed=sorted(req - said), extra=sorted(said - req - opt)))
med = lambda xs: st.median(xs) if xs else 0
print("%-9s %4s %7s %7s %6s %11s %7s %6s" % ("tool", "runs", "recall", "prec", "calls", "tokens/goal", "$/goal", "wall"))
for tool, rs in rows.items():
    print("%-9s %4d %7.2f %7.2f %6.0f %10.0fk %7.3f %6.0f   total $%.2f, unfinished %d" % (
        tool, len(rs), st.mean(r["recall"] for r in rs), st.mean(r["prec"] for r in rs), med([r["calls"] for r in rs]),
        med([r["tokens"] for r in rs]) / 1000, med([r["cost"] for r in rs]), med([r["wall"] for r in rs]),
        sum(r["cost"] for r in rs), sum(not r["ok"] for r in rs)))
if "-v" in sys.argv:
    for tool, rs in rows.items():
        for r in rs:
            print("%s %s.%s recall %.2f prec %.2f calls %d tokens %dk wall %.0fs missed %s extra %s" % (
                tool, r["name"], r["rep"], r["recall"], r["prec"], r["calls"], r["tokens"] / 1000, r["wall"], r["missed"][:6], r["extra"][:6]))
