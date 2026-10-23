#!/usr/bin/env python3
"""usage: after_scan.py BIN DIR APK OUT.json [global args...]
One MCP server: a cold rules sweep over DIR (836 APKs), then right away, while the cache
writers re-inflate deferred L1 entries, a series of queries; latency of each.
Queries: a findrefs over DIR for a different rule (sweep), and single-APK findrefs on APK."""
import json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common import Mcp
BIN, DIR, APK, OUT, *EXTRA = sys.argv[1:]
RULES = [{"kind": "string", "value": "http://"}, {"kind": "string", "value": "password"},
         {"kind": "type", "value": "Ldalvik/system/DexClassLoader;"}, {"kind": "method", "name": "exec", "class": "java.lang.Runtime"}]
m = Mcp([BIN, *EXTRA, "mcp"])
def call(args):
    t = time.perf_counter(); r = m.call("findrefs", dict(args, spill="never", max_bytes=1 << 30)); ms = (time.perf_counter() - t) * 1000
    assert not r.get("isError"), r
    return round(ms, 1)
res = {"sweep": call({"rules": RULES, "dir": DIR})}
t0 = time.perf_counter(); q = []
for i in range(12):
    q.append(("apk-" + str(i), call({"apk": APK, "kind": "method", "name": "getDeviceId", "class": "android.telephony.TelephonyManager"})))
    q.append(("dir-" + str(i), call({"dir": DIR, "kind": "method", "name": ["getSubscriberId", "getLine1Number", "getSimSerialNumber", "getImei", "getMeid", "getDeviceId", "loadLibrary", "load", "exec", "setJavaScriptEnabled", "addJavascriptInterface", "getInstalledPackages"][i]})))
res["queries"] = q
res["after_ms"] = round((time.perf_counter() - t0) * 1000)
m.p.stdin.close(); t = time.perf_counter(); m.p.wait(); res["exit_ms"] = round((time.perf_counter() - t) * 1000)
json.dump(res, open(OUT, "w"))
print(json.dumps(res))
