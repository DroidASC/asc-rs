#!/usr/bin/env python3
"""usage: failed.py RUN_DIR... > failed.jsonl — droidasc MCP calls that failed, with their error text."""
import glob, json, os, sys
out = []
for d in sys.argv[1:]:
    for p in sorted(glob.glob(os.path.join(d, "*.ndjson"))):
        tool = os.path.basename(p).split(".")[0]
        if tool not in ("droidasc", "dnewA", "dnewB", "dr1"):
            continue
        calls = {}
        for l in open(p):
            if not l.strip(): continue
            e = json.loads(l)
            if e.get("type") == "tool_call" and e.get("toolName") == "use_tool":
                calls[e["toolCallId"]] = e.get("rawInput") or {}
            elif e.get("type") == "tool_call_update" and e.get("toolCallId") in calls:
                raw = e.get("rawOutput")
                s = json.dumps(raw, ensure_ascii=False) if raw is not None else ""
                failed = e.get("status") == "failed" or '"isError": true' in s or "Error:" in s[:200]
                if failed and raw is not None:
                    inp = calls.pop(e["toolCallId"])
                    out.append({"run": os.path.basename(p), "group": tool, "input": inp, "error": s[:600]})
for o in out:
    print(json.dumps(o, ensure_ascii=False))
