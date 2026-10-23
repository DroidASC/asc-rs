#!/usr/bin/env python3
"""Exposure-surface audit over a directory of APKs through one `droidasc mcp`.

Compares an agent that calls findrefs once per APK per rule with one that
calls it once per rule over the whole directory (`dir`), following cursors.

usage: audit.py DROIDASC APK_DIR [per-apk|multi|multi-first|all] [extra droidasc args...]

  per-apk      RULES x APKs findrefs calls, all pipelined at once (no agent can go faster)
  per-apk-rule the same calls one rule at a time: a rule's APKs pipelined, then wait
  multi        one findrefs per rule with `dir`, then every cursor page
  multi-first  one findrefs per rule with `dir`, first page only

Reported: tool calls, reply text bytes (what lands in the agent's context),
wall time, peak RSS of the server, and the hits seen.
"""
import json, os, subprocess, sys, threading, time

RULES = [
    {"kind": "string", "value": "http://"},
    {"kind": "string", "value": "password"},
    {"kind": "type", "value": "Ldalvik/system/DexClassLoader;"},
    {"kind": "method", "name": "exec", "class": "java.lang.Runtime"},
    {"kind": "method", "name": "addJavascriptInterface"},
    {"kind": "method", "name": "setJavaScriptEnabled"},
    {"kind": "method", "name": "getDeviceId"},
    {"kind": "method", "name": "loadLibrary", "class": "java.lang.System"},
]


def peak_rss(pid, stop, out):
    """Peak RSS and peak anonymous RSS (heap; the rest is file pages the kernel can reclaim), MB."""
    peak = anon = 0
    while not stop.is_set():
        try:
            for l in open(f"/proc/{pid}/status"):
                if l.startswith("VmRSS:"):
                    peak = max(peak, int(l.split()[1]))
                elif l.startswith("RssAnon:"):
                    anon = max(anon, int(l.split()[1]))
        except OSError:
            break
        time.sleep(0.02)
    out.extend([peak // 1024, anon // 1024])


class Server:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, bufsize=1)
        self.next_id = 0
        self.calls = 0
        self.bytes = 0
        self.send({"method": "initialize", "params": {}})
        self.recv()

    def send(self, msg):
        self.next_id += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.next_id, **msg}) + "\n")
        return self.next_id

    def call(self, args):
        self.calls += 1
        return self.send({"method": "tools/call", "params": {"name": "findrefs", "arguments": args}})

    def recv(self):
        msg = json.loads(self.p.stdout.readline())
        if "result" in msg and "content" in msg["result"]:
            self.bytes += len(msg["result"]["content"][0]["text"].encode())
        return msg

    def close(self):
        self.p.stdin.close()
        self.p.wait()


def run(bin_, apk_dir, mode, extra):
    apks = sorted(os.path.join(r, f) for r, _, fs in os.walk(apk_dir) for f in fs if f.endswith(".apk"))
    s = Server([bin_, *extra, "mcp"])
    stop, peak = threading.Event(), []
    mon = threading.Thread(target=peak_rss, args=(s.p.pid, stop, peak))
    mon.start()
    t = time.perf_counter()
    hits = 0
    errors = 0
    if mode.startswith("per-apk"):
        waves = [RULES] if mode == "per-apk" else [[r] for r in RULES]
        for wave in waves:
            n = 0
            for rule in wave:
                for a in apks:
                    s.call({"apk": a, **rule})
                    n += 1
            s.p.stdin.flush()
            for _ in range(n):
                r = s.recv()["result"]
                if r.get("isError"):
                    errors += 1
                else:
                    hits += r["structuredContent"]["total"]
    else:
        more = json.loads(os.environ.get("AUDIT_ARGS", "{}"))
        for rule in RULES:
            t1 = time.perf_counter()
            s.call({"dir": apk_dir, **rule, **more})
            s.p.stdin.flush()
            r = s.recv()["result"]
            if os.environ.get("AUDIT_VERBOSE"):
                print(f"  {rule}: {(time.perf_counter() - t1) * 1000:.0f} ms", file=sys.stderr)
            if r.get("isError"):
                print("error:", r["content"][0]["text"][:200], file=sys.stderr)
                errors += 1
                continue
            sc = r["structuredContent"]
            hits += sc["total"]
            errors += sc["errors"]
            cursor = sc["cursor"]
            while cursor and mode == "multi":
                s.call({"cursor": cursor})
                s.p.stdin.flush()
                cursor = s.recv()["result"]["structuredContent"]["cursor"]
    ms = (time.perf_counter() - t) * 1000
    s.close()
    stop.set()
    mon.join()
    print(f"{mode:12s} {len(apks)} APKs  calls {s.calls:5d}  reply text {s.bytes / 1024:8.1f} KiB  "
          f"{ms:7.0f} ms  peak RSS {peak[0]:5d} MB (anon {peak[1]:5d})  hits {hits}  errors {errors}")


if __name__ == "__main__":
    bin_, apk_dir = sys.argv[1], sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "all"
    extra = sys.argv[4:]
    for m in (["per-apk", "per-apk-rule", "multi", "multi-first"] if mode == "all" else [mode]):
        run(bin_, apk_dir, m, extra)
