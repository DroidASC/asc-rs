"""Shared bits of the macOS benchmarks: MCP client, peak RSS of a process (tree)."""
import json, os, subprocess, sys, threading, time
# droidasc forwards one-shot commands to its daemon by default; measure without it unless asked.
os.environ.setdefault("DROIDASC_DAEMON", "off")

DARWIN = sys.platform == "darwin"


def maxrss_mb(ru):
    # ru_maxrss is bytes on macOS, KiB on Linux.
    return ru.ru_maxrss // (1 << 20) if DARWIN else ru.ru_maxrss // 1024


def run_measured(cmd, stdout=subprocess.PIPE):
    """Run cmd to completion: (stdout bytes, peak RSS MB, exit status)."""
    p = subprocess.Popen(cmd, stdout=stdout, stderr=subprocess.DEVNULL)
    out = p.stdout.read() if stdout == subprocess.PIPE else b""
    _, status, ru = os.wait4(p.pid, 0)
    p.returncode = status
    return out, maxrss_mb(ru), status


class TreeSampler:
    """Peak over time of the summed RSS of some roots and all their descendants (ps polling)."""

    def __init__(self, pids, period=0.05):
        self.roots, self.period, self.peak = set(pids), period, 0
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def sample(self):
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,rss="], capture_output=True, text=True).stdout
        rows = [tuple(map(int, l.split())) for l in out.splitlines() if l.strip()]
        kids = {}
        for pid, ppid, rss in rows:
            kids.setdefault(ppid, []).append(pid)
        rss = {pid: r for pid, _, r in rows}
        seen, todo = set(), list(self.roots)
        while todo:
            p = todo.pop()
            if p in seen:
                continue
            seen.add(p)
            todo.extend(kids.get(p, []))
        return sum(rss.get(p, 0) for p in seen) // 1024

    def loop(self):
        while not self.stop.is_set():
            self.peak = max(self.peak, self.sample())
            time.sleep(self.period)

    def finish(self):
        self.stop.set()
        self.t.join()
        return self.peak


class Mcp:
    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.i = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}})
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def write(self, m):
        self.p.stdin.write(json.dumps(m) + "\n")
        self.p.stdin.flush()

    def request(self, method, params):
        self.i += 1
        self.write({"jsonrpc": "2.0", "id": self.i, "method": method, "params": params})
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("MCP server exited")
            m = json.loads(line)
            if m.get("id") == self.i:
                return m.get("result", {"isError": True, "error": m.get("error")})

    def call(self, name, args):
        return self.request("tools/call", {"name": name, "arguments": args})

    def tool_names(self):
        return {t["name"]: set(t["inputSchema"].get("properties", {})) for t in self.request("tools/list", {})["tools"]}

    def close(self):
        """Close stdin and reap: peak RSS MB of the server process itself."""
        self.p.stdin.close()
        _, _, ru = os.wait4(self.p.pid, 0)
        self.p.returncode = 0
        return maxrss_mb(ru)


def text(result):
    return "".join(c.get("text", "") for c in result.get("content", []))
