#!/usr/bin/env python3
"""Per-run metrics of grok headless transcripts (streaming-json ndjson), as CSV on stdout.

usage: extract.py s1 RUNS_DIR ROUND            (evidence from $HARNESS/rasc_replay.py SCENARIOS)
       extract.py s2 RUNS_DIR ROUND REF.json   (recall / precision of the `APK:` answer lines)

Run files are named <group>.<goal>.<rep>.ndjson. Columns: round, group, goal, rep, finished,
calls (every tool_call event), mcp_calls (those
through grok's `use_tool`, i.e. MCP tools: the "calls" of the summaries), failed (tool_call_update status=failed), tokens (end.usage.total_tokens),
cost_usd, wall_s, attempts (rate-limit retries + 1), tool_out_kb, evidence_hit / evidence_total (s1)
or recall / precision / missed / extra (s2), and tool_calls (JSON: calls per tool name).
"""
import collections, csv, glob, json, os, re, runpy, sys

KIND, RUNS, ROUND = sys.argv[1:4]
if KIND == "s1":
    H = os.environ["HARNESS"]
    SC = runpy.run_path(os.path.join(H, "rasc_replay.py"), run_name="x")["SCENARIOS"]
else:
    REF = json.load(open(sys.argv[4]))


def tool_name(e):
    name = e.get("toolName") or "?"
    if name == "use_tool":
        inp = e.get("rawInput") or e.get("input") or {}
        name = inp.get("tool_name") or inp.get("name") or name
    return name


cols = ["round", "group", "goal", "rep", "finished", "calls", "mcp_calls", "failed", "tokens", "cost_usd", "wall_s", "attempts", "tool_out_kb"]
cols += ["evidence_hit", "evidence_total"] if KIND == "s1" else ["recall", "precision", "missed", "extra"]
cols += ["tool_calls"]
w = csv.DictWriter(sys.stdout, cols)
w.writeheader()
for p in sorted(glob.glob(os.path.join(RUNS, "*.ndjson"))):
    group, goal, rep = os.path.basename(p)[:-len(".ndjson")].rsplit(".", 2)
    ev = [json.loads(l) for l in open(p) if l.strip()]
    end = next((e for e in ev if e.get("type") == "end"), {})
    wall = next((e for e in ev if e.get("type") == "wall"), {})
    calls = [e for e in ev if e.get("type") == "tool_call"]
    outs = [json.dumps(e.get("rawOutput", {}), ensure_ascii=False) for e in ev if e.get("type") == "tool_call_update"]
    answer = "".join(e["data"] for e in ev if e.get("type") == "text" and isinstance(e.get("data"), str))
    row = dict(round=ROUND, group=group, goal=goal, rep=rep, finished=int(end.get("stopReason") == "end_turn"), calls=len(calls),
               mcp_calls=sum(e.get("toolName") == "use_tool" for e in calls),
               failed=sum(e.get("type") == "tool_call_update" and e.get("status") == "failed" for e in ev),
               tokens=end.get("usage", {}).get("total_tokens", 0), cost_usd=round(end.get("total_cost_usd", 0) or 0, 5),
               wall_s=round(wall.get("seconds", 0), 1), attempts=wall.get("attempts", 1),
               tool_out_kb=round(sum(map(len, outs)) / 1024, 1),
               tool_calls=json.dumps(dict(collections.Counter(map(tool_name, calls)).most_common()), sort_keys=False))
    if KIND == "s1":
        exp = SC[goal]["expect"]
        joined = "".join(outs)
        row.update(evidence_hit=sum(x in joined or x in answer for x in exp), evidence_total=len(exp))
    else:
        said = {m.strip(" `*") for m in re.findall(r"APK:\s*`?([A-Za-z0-9_.]+)", answer)}
        said = {s[:-4] if s.endswith(".apk") else s for s in said}
        req, opt = set(REF[goal]["required"]), set(REF[goal]["optional"])
        tp, fp = len(said & req), len(said - req - opt)
        row.update(recall=round(tp / len(req), 3), precision=round(tp / max(1, tp + fp), 3),
                   missed=" ".join(sorted(req - said)), extra=" ".join(sorted(said - req - opt)))
    w.writerow(row)
