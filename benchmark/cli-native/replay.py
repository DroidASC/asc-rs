#!/usr/bin/env python3
"""Failed-call replay (round 2, cli-native): every droidasc MCP call that failed in the grok runs,
replayed on one build.

usage: replay.py BIN APK failed-calls.jsonl — replay each failed droidasc call in one MCP session.

APK paths are rewritten to APK (opened first as apk1). Prints one JSON line per call:
group, tool, ok, actionable, first 300 chars of the reply text."""
import json, re, subprocess, sys
BIN, APK, SRC = sys.argv[1:4]
ACTIONABLE = re.compile(r"did you mean|its methods|has no method|; .* has |framework class|closest:|# hint:|exists \(|no DEX references|e\.g\.|use string|there is no page \d+: this output has|may be renamed|may be obfuscated|needs `|must be a complete query|pass the `cursor`|pass `apk", re.S)
p = subprocess.Popen([BIN, "mcp", "--no-cache"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def rpc(m):
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline()) if "id" in m else None
rpc({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "r", "version": "1"}}})
rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})
rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "open_apk", "arguments": {"apk": APK, "warm": False}}})
def fix(v):
    if isinstance(v, dict): return {k: (APK if k == "apk" else fix(x)) for k, x in v.items()}
    if isinstance(v, list): return [fix(x) for x in v]
    return v
n = 0
for i, l in enumerate(open(SRC)):
    r = json.loads(l)
    name = r["input"].get("tool_name", "")
    if not name.startswith("droidasc__"):
        continue
    args = fix(r["input"].get("tool_input") or {})
    rep = rpc({"jsonrpc": "2.0", "id": 100 + i, "method": "tools/call", "params": {"name": name[len("droidasc__"):], "arguments": args}})
    res = rep.get("result") or {}
    txt = (res.get("content") or [{}])[0].get("text", "") if res else json.dumps(rep.get("error"))
    ok = res.get("isError") is False
    print(json.dumps({"n": n, "group": r["group"], "tool": name, "ok": ok, "actionable": bool(ACTIONABLE.search(txt)), "text": txt[:300]}, ensure_ascii=False))
    n += 1
p.kill()
