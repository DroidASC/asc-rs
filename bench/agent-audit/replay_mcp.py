#!/usr/bin/env python3
"""Replay the dexsql-release agent-audit goals against `droidasc mcp`.

The 17 goals and their steps come from dexsql-release's
benchmarks/agent-audit/harness/rasc_replay.py (SCENARIOS), imported at run
time from $HARNESS; nothing of theirs is copied here. Each rasc CLI step is
translated to the matching MCP tool call, so both tools do the same lookups.

Measured like dexsql_replay.py / whole_suite.py:
  * whole session: a new `droidasc mcp` process per trial: initialize,
    open_apk (inflates every DEX), every goal once, close; median of TRIALS;
  * hot per goal: one session, goals shuffled with seed 1937, TRIALS each,
    median per goal, geometric mean over goals;
  * peak RSS (VmHWM) of the server process at the end of a session.
The class inventory goal is excluded, as in the dexsql report.

Environment: HARNESS (dexsql-release/benchmarks/agent-audit/harness),
APK (douyin-40.7.0.apk), DROIDASC (default target/release/droidasc),
DROIDASC_THREADS (default: droidasc's default), DROIDASC_ARGS (extra
global flags, e.g. "--no-cache"). Writes results/asc_mcp_benchmark.json.
"""

from __future__ import annotations

import json
import os
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
HARNESS = Path(os.environ["HARNESS"])
sys.path.insert(0, str(HARNESS))
import rasc_replay as rr  # noqa: E402

APK = str(Path(os.environ.get("APK", "douyin-40.7.0.apk")).resolve())
BIN = os.environ.get("DROIDASC", str(REPO / "target/release/droidasc"))
THREADS = os.environ.get("DROIDASC_THREADS")
EXTRA = os.environ.get("DROIDASC_ARGS", "").split()
TRIALS = 7
EXCLUDED = {"class_inventory"}


class McpClient:
    def __init__(self) -> None:
        cmd = [BIN, *EXTRA, *(["--threads", THREADS] if THREADS else []), "mcp"]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.next_id = 1
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "asc-agent-audit", "version": "1"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")

    def request(self, method: str, params: dict) -> dict:
        ident = self.next_id
        self.next_id += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        msg = json.loads(self.p.stdout.readline())
        if "error" in msg:
            raise RuntimeError(f"{method}: {msg['error']}")
        return msg["result"]

    def tool(self, name: str, arguments: dict) -> str:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(f"tool {name} failed: {result['content'][0]['text']}")
        return result["content"][0]["text"]

    def peak_rss_mb(self) -> float:
        for line in open(f"/proc/{self.p.pid}/status"):
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024
        return 0.0

    def close(self) -> None:
        self.p.stdin.close()
        self.p.wait(timeout=30)


def translate(cmd: list[str]) -> tuple[str, dict]:
    """One rasc CLI step as an MCP tool call (apk_id filled in later)."""
    args = [a for a in cmd[1:] if a != str(rr.APK)]
    if "--threads" in args:
        i = args.index("--threads")
        del args[i:i + 2]
    sub, rest = args[0], args[1:]
    if sub == "manifest":
        return "getmanifest", {}
    if sub == "classes":
        return "listclass", {}
    if sub == "getclass":
        return "getclass", {"class": rest[0]}
    if sub == "findrefs":
        kind, rest = rest[0], rest[1:]
        if kind in ("string", "type"):
            return "findrefs", {"kind": kind, "value": rest[0]}
        call = {"kind": kind, "name": rest[0]}
        if "--class" in rest:
            call["class"] = rest[rest.index("--class") + 1]
        return "findrefs", call
    raise ValueError(f"untranslated step: {cmd}")


GOALS = {name: [translate(c) for c in spec["steps"]] for name, spec in rr.SCENARIOS.items() if name not in EXCLUDED}


def run_goal(client: McpClient, apk_id: str, steps: list[tuple[str, dict]]) -> str:
    return "\n".join(client.tool(name, {"apk_id": apk_id, **args}) for name, args in steps)


def session_trial() -> dict:
    start = time.perf_counter()
    client = McpClient()
    init_ms = (time.perf_counter() - start) * 1000
    t = time.perf_counter()
    opened = client.request("tools/call", {"name": "open_apk", "arguments": {"apk": APK}})["structuredContent"]
    open_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    for steps in GOALS.values():
        run_goal(client, opened["apk_id"], steps)
    hot_suite_ms = (time.perf_counter() - t) * 1000
    rss = client.peak_rss_mb()
    client.close()
    return {"mcp_init_ms": init_ms, "open_ms": open_ms, "hot_suite_ms": hot_suite_ms,
            "total_process_ms": (time.perf_counter() - start) * 1000, "peak_rss_mb": rss}


def main() -> None:
    client = McpClient()
    apk_id = client.request("tools/call", {"name": "open_apk", "arguments": {"apk": APK}})["structuredContent"]["apk_id"]
    validation = {}
    for name, steps in GOALS.items():
        out = run_goal(client, apk_id, steps)
        validation[name] = [t for t in rr.SCENARIOS[name].get("expect", []) if t not in out]
    samples = {name: [] for name in GOALS}
    order = [name for name in GOALS for _ in range(TRIALS)]
    random.Random(1937).shuffle(order)
    for name in order:
        t = time.perf_counter()
        run_goal(client, apk_id, GOALS[name])
        samples[name].append((time.perf_counter() - t) * 1000)
    hot_rss = client.peak_rss_mb()
    client.close()

    sessions = [session_trial() for _ in range(TRIALS)]
    medians = {k: statistics.median(s[k] for s in sessions) for k in sessions[0]}
    hot = {name: statistics.median(v) for name, v in samples.items()}
    report = {
        "binary": BIN, "apk": APK, "threads": THREADS, "extra_args": EXTRA, "trials": TRIALS,
        "session_medians": medians, "sessions": sessions,
        "hot_median_ms": hot, "hot_geomean_ms": statistics.geometric_mean(hot.values()),
        "hot_session_peak_rss_mb": hot_rss,
        "missing_tokens": {k: v for k, v in validation.items() if v},
    }
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "asc_mcp_benchmark.json").write_text(json.dumps(report, indent=1, ensure_ascii=False))
    for name, ms in hot.items():
        print(f"{name:32s} hot {ms:7.1f} ms")
    print(f"open {medians['open_ms']:.0f} ms, whole session {medians['total_process_ms']:.0f} ms, "
          f"hot suite {medians['hot_suite_ms']:.0f} ms, hot geomean {report['hot_geomean_ms']:.1f} ms, "
          f"peak RSS {medians['peak_rss_mb']:.0f} MB")
    if report["missing_tokens"]:
        print("missing expected tokens (Java spellings vs smali, check by hand):", report["missing_tokens"])


if __name__ == "__main__":
    main()
