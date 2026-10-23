#!/usr/bin/env python3
"""usage: summary.py ROOT TAG [-v]   (medians per group of ROOT/runs/TAG/*.ndjson; calls = MCP calls via use_tool)"""
import glob, json, os, runpy, statistics as st, sys, collections
ROOT, TAG = sys.argv[1:3]
# dexsql-release benchmarks/agent-audit/harness (its SCENARIOS are imported, not copied).
H = os.environ.get("HARNESS") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dexsql-release/benchmarks/agent-audit/harness")
SC = runpy.run_path(os.path.join(H, "rasc_replay.py"), run_name="x")["SCENARIOS"]
rows = collections.defaultdict(list)
for p in sorted(glob.glob(os.path.join(ROOT, "runs", TAG, "*.ndjson"))):
    tool, name, rep = os.path.basename(p).split(".")[:3]
    ev = [json.loads(l) for l in open(p) if l.strip()]
    end = next((e for e in ev if e.get("type") == "end"), {})
    wall = next((e["seconds"] for e in ev if e.get("type") == "wall"), 0)
    calls = [e for e in ev if e.get("type") == "tool_call" and e.get("toolName") == "use_tool"]
    fails = [e for e in ev if e.get("type") == "tool_call_update" and e.get("status") == "failed"]
    outs = "".join(json.dumps(e.get("rawOutput", {}), ensure_ascii=False) for e in ev if e.get("type") == "tool_call_update")
    out_bytes = sum(len(json.dumps(e.get("rawOutput", {}), ensure_ascii=False)) for e in ev if e.get("type") == "tool_call_update")
    answer = "".join(e["data"] for e in ev if e.get("type") == "text" and isinstance(e.get("data"), str))
    exp = SC[name]["expect"]
    hit = sum(1 for x in exp if x in outs or x in answer)
    u = end.get("usage", {})
    rows[tool].append(dict(name=name, calls=len(calls), fails=len(fails), tokens=u.get("total_tokens", 0),
                           cost=end.get("total_cost_usd", 0), wall=wall, ev=hit, exp=len(exp), outkb=out_bytes / 1024,
                           ok=end.get("stopReason") == "end_turn"))
def med(xs): return st.median(xs) if xs else 0
print(f"{'tool':9} {'runs':>4} {'calls/goal':>10} {'failed':>6} {'tokens/goal':>11} {'$/goal':>7} {'wall s':>6} {'tool out KB':>11} {'evidence':>9} {'full ev':>7}")
for tool, rs in rows.items():
    full = sum(r["ev"] == r["exp"] for r in rs)
    print(f"{tool:9} {len(rs):4} {med([r['calls'] for r in rs]):10.1f} {sum(r['fails'] for r in rs):6} {med([r['tokens'] for r in rs])/1000:10.0f}k "
          f"{med([r['cost'] for r in rs]):7.3f} {med([r['wall'] for r in rs]):6.0f} {med([r['outkb'] for r in rs]):11.1f} "
          f"{sum(r['ev'] for r in rs)}/{sum(r['exp'] for r in rs):<5} {full}/{len(rs)}")
    print(f"          total ${sum(r['cost'] for r in rs):.2f}, {sum(r['tokens'] for r in rs)/1e6:.1f}M tokens, not finished {sum(not r['ok'] for r in rs)}")
if "-v" in sys.argv:
    names = sorted({r["name"] for rs in rows.values() for r in rs})
    print(f"\n{'goal':30} " + "  ".join(f"{t:>26}" for t in rows))
    for n in names:
        cells = []
        for t, rs in rows.items():
            g = [r for r in rs if r["name"] == n]
            calls = "/".join(str(r["calls"]) for r in g)
            evs = "/".join("%d/%d" % (r["ev"], r["exp"]) for r in g)
            cells.append("%8s calls %11s ev" % (calls, evs))
        print(f"{n:30} " + "  ".join(f"{c:>26}" for c in cells))
