"""rust_ASC vs droidasc (round 1): APK-level hit sets of the 8 S2 rules over a corpus dir
(rust_ASC CLI per APK x rule vs one droidasc MCP), and the rows that differ.

usage: s2diff.py RUST_ASC DROIDASC CORPUS_DIR
"""
import concurrent.futures as cf, json, os, re, subprocess, sys
# droidasc forwards one-shot commands to its daemon by default; measure without it unless asked.
os.environ.setdefault("DROIDASC_DAEMON", "off")
R, B, D = sys.argv[1:4]
RULES = [["string","http://"],["string","password"],["type","Ldalvik/system/DexClassLoader;"],["method","exec","--class","java.lang.Runtime"],
 ["method","addJavascriptInterface"],["method","setJavaScriptEnabled"],["method","getDeviceId"],["method","loadLibrary","--class","java.lang.System"]]
apks = sorted(os.path.join(D,f) for f in os.listdir(D) if f.endswith(".apk"))
ROW = re.compile(rb"^classes\d*\.dex \| ", re.M)
def rust(job):
    a, r = job
    out = subprocess.run([R,"findrefs","--thread","1",a,*r],capture_output=True).stdout
    return len(ROW.findall(out))
jobs = [(a,r) for a in apks for r in RULES]
with cf.ThreadPoolExecutor(16) as ex: rc = list(ex.map(rust, jobs))
p = subprocess.Popen([B,"--no-cache","mcp"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
for i,(a,r) in enumerate(jobs):
    args={"apk":a,"kind":r[0],"limit":10**6}
    if r[0] in ("string","type"): args["value"]=r[1]
    else:
        args["name"]=r[1]
        if "--class" in r: args["class"]=r[3]
    p.stdin.write(json.dumps({"jsonrpc":"2.0","id":i,"method":"tools/call","params":{"name":"findrefs","arguments":args}})+"\n")
p.stdin.close()
ac={}
for l in p.stdout.read().split("\n"):
    if l.strip():
        m=json.loads(l); ac[m["id"]]=m["result"]["structuredContent"]["total"]
diff=[(os.path.basename(jobs[i][0]),jobs[i][1],rc[i],ac[i]) for i in range(len(jobs)) if rc[i]!=ac[i]]
print("rust records", sum(rc), "asc records", sum(ac.values()), "mismatching pairs", len(diff))
for d in diff[:12]: print(" ", d)
