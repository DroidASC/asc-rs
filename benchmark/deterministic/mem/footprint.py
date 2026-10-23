#!/usr/bin/env python3
"""Run CMD (an s2.py run); while it runs, sample the droidasc processes under it:
summed RSS every 0.5 s, and `footprint` (per-category dirty/clean, summed over the
processes) every PERIOD s. Prints the time course and the category breakdown at the
sample with the largest total footprint; writes OUT.json.
usage: footprint.py OUT.json PERIOD CMD...   (macOS: needs `footprint`; scratch file under $BENCH_TMP)
e.g. AUTO=1 footprint.py n16.mem.json 0.3 python3 ../s2.py mcprules BIN n16.json 16 -- --cache-dir C"""
import json, os, subprocess, sys, threading, time

out_path, period, cmd = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
root = subprocess.Popen(cmd)
t0 = time.time()


def droidascs():
    ps = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,comm="], capture_output=True, text=True).stdout
    rows = []
    for l in ps.splitlines():
        p = l.split(None, 3)
        if len(p) == 4:
            rows.append((int(p[0]), int(p[1]), int(p[2]), p[3]))
    kids = {}
    for pid, ppid, _, _ in rows:
        kids.setdefault(ppid, []).append(pid)
    seen, stack = set(), [root.pid]
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(kids.get(p, []))
    return {pid: rss for pid, _, rss, comm in rows if pid in seen and comm.endswith("droidasc")}


rss_course, fp_samples, pid_peak = [], [], {}
stop = threading.Event()


def rss_loop():
    while not stop.is_set():
        d = droidascs()
        rss_course.append((round(time.time() - t0, 1), len(d), sum(d.values()) // 1024))
        time.sleep(0.5)


threading.Thread(target=rss_loop, daemon=True).start()
while root.poll() is None:
    pids = list(droidascs())
    if pids:
        j = os.path.join(os.environ.get("BENCH_TMP", "/private/tmp/asc-bench"), "fp.json")
        ts = time.time() - t0
        r = subprocess.run(["footprint", "-f", "bytes", "--swapped", "-j", j, *map(str, pids)], capture_output=True, text=True)
        try:
            data = json.load(open(j))
        except Exception:
            data = None
        if data:
            cats, total, procs = {}, 0, 0
            for p in data.get("processes", []):
                procs += 1
                total += p.get("footprint", 0)
                pk = (p.get("auxiliary") or {}).get("phys_footprint_peak", 0)
                pid_peak[p.get("pid")] = max(pid_peak.get(p.get("pid"), 0), pk)
                for name, v in (p.get("categories") or {}).items():
                    acc = cats.setdefault(name, [0, 0, 0])
                    acc[0] += v.get("dirty", 0)
                    acc[1] += v.get("clean", 0)
                    acc[2] += v.get("swapped", 0)
            fp_samples.append(dict(t=round(ts, 1), procs=procs, footprint=total, cats=cats, raw_keys=list(data.keys())))
            if len(fp_samples) == 1:
                json.dump(data, open(out_path + ".first-raw.json", "w"))
    time.sleep(period)
stop.set()
peak = max(fp_samples, key=lambda s: s["footprint"]) if fp_samples else None
json.dump(dict(rss=rss_course, footprint=fp_samples, peak=peak, pid_peak=pid_peak, rc=root.returncode), open(out_path, "w"))
print("sum of per-process phys_footprint_peak MB %d over %d procs" % (sum(pid_peak.values()) >> 20, len(pid_peak)))
print("wall %.1f s; rss peak MB %d" % (time.time() - t0, max((r[2] for r in rss_course), default=0)))
for s in fp_samples:
    print("t=%6.1f procs=%2d footprint=%6d MB" % (s["t"], s["procs"], s["footprint"] >> 20))
if peak:
    print("peak t=%.1f footprint %d MB over %d procs" % (peak["t"], peak["footprint"] >> 20, peak["procs"]))
    for name, (d, c, sw) in sorted(peak["cats"].items(), key=lambda kv: -kv[1][0])[:15]:
        print("  %-36s dirty %6d MB  clean %6d MB  swapped %5d MB" % (name, d >> 20, c >> 20, sw >> 20))
