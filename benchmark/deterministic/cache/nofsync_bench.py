#!/usr/bin/env python3
"""no-fsync (round 2): cold / warm / after-reboot cache timings of two builds, alternating.

usage: nofsync_bench.py BASE NEW DOUYIN_APK CORPUS_DIR CACHE_ROOT TRIALS
"""
import concurrent.futures as cf, os, shutil, statistics as st, subprocess, sys, time
# droidasc forwards one-shot commands to its daemon by default; measure without it unless asked.
os.environ.setdefault("DROIDASC_DAEMON", "off")
BASE, NEW, APK, CORPUS, ROOT, N = sys.argv[1:6] + [int(sys.argv[6])]
Q = ["findrefs", APK, "method", "exec", "--class", "java.lang.Runtime"]
RULES = ["string:http://", "string:password", "type:Ldalvik/system/DexClassLoader;", "method:java.lang.Runtime->exec",
         "method:addJavascriptInterface", "method:setJavaScriptEnabled", "method:getDeviceId", "method:java.lang.System->loadLibrary"]
apks = sorted(os.path.join(CORPUS, f) for f in os.listdir(CORPUS) if f.endswith(".apk"))

def fresh(tag):
    d = os.path.join(ROOT, tag)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    subprocess.run(["sync"])
    return d

NO_L3 = dict(os.environ, DROIDASC_CACHE_TIERS="dex,derived")

def run(b, d, args, env=None):
    t = time.time()
    subprocess.run([b, "--cache-dir", d, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    return time.time() - t

def s2(b, d, env=None):
    t = time.time()
    with cf.ThreadPoolExecutor(16) as ex:
        list(ex.map(lambda a: run(b, d, ["findrefs", a, "rules", *RULES, "--threads", "1"], env), apks))
    return time.time() - t

def age(d):
    old = time.time() - 2 * 86400
    for r, _, fs in os.walk(d):
        for f in fs:
            os.utime(os.path.join(r, f), (old, old))

res = {k: {"base": [], "new": []} for k in ("douyin cold", "douyin warm", "douyin after reboot", "douyin 2nd after reboot", "s2 cold", "s2 warm", "s2 after reboot")}
for i in range(N):
    for name, b in (("base", BASE), ("new", NEW)) if i % 2 == 0 else (("new", NEW), ("base", BASE)):
        d = fresh(name)
        res["douyin cold"][name].append(run(b, d, Q))
        res["douyin warm"][name].append(run(b, d, Q, NO_L3))
        age(d)
        res["douyin after reboot"][name].append(run(b, d, Q, NO_L3))
        res["douyin 2nd after reboot"][name].append(run(b, d, Q, NO_L3))
        d = fresh(name)
        res["s2 cold"][name].append(s2(b, d))
        res["s2 warm"][name].append(s2(b, d, NO_L3))
        age(d)
        res["s2 after reboot"][name].append(s2(b, d, NO_L3))
        du = subprocess.run(["du", "-sm", d], capture_output=True, text=True).stdout.split()[0]
        print(i, name, "cache MB", du, flush=True)
for k, v in res.items():
    print("%-26s base %7.0f ms   new %7.0f ms" % (k, st.median(v["base"]) * 1000, st.median(v["new"]) * 1000))
shutil.rmtree(ROOT, ignore_errors=True)
