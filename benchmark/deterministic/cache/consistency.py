"""Cache consistency (round 1, D line): 40 random APKs of CORPUS_DIR x 9 queries, output with the
disk cache (cold, then warm) compared block-wise with --no-cache.

usage: consistency.py DROIDASC CORPUS_DIR CACHE_DIR
"""
import re
import os, random, subprocess, sys, hashlib
# droidasc forwards one-shot commands to its daemon by default; measure without it unless asked.
os.environ.setdefault("DROIDASC_DAEMON", "off")
bin_, corpus, cache = sys.argv[1:4]
RULES = [["string","http://"],["string","password"],["type","Ldalvik/system/DexClassLoader;"],["method","exec","--class","java.lang.Runtime"],
 ["method","addJavascriptInterface"],["method","loadLibrary","--class","java.lang.System"],["field","SDK_INT"],["impl","android.content.ServiceConnection"],
 ["string","https?://[a-z]+","--context","2"]]
apks = sorted(os.path.join(corpus,f) for f in os.listdir(corpus) if f.endswith(".apk"))
random.seed(7); pairs=[(a,r) for a in random.sample(apks,40) for r in RULES]
env=dict(os.environ, DROIDASC_CACHE_DIR=cache)
def run(args, cached):
    cmd=[bin_]+([] if cached else ["--no-cache"])+args
    p=subprocess.run(cmd,capture_output=True,env=env)
    if args[0]!="findrefs": return p.returncode, p.stdout
    out=p.stdout.decode(errors="replace").rstrip("\n")
    return p.returncode, sorted(re.split(r"\n(?=classes\d*\.dex \| )", out))
bad=0
for rnd in range(2):
    for a,r in pairs:
        args=["findrefs",a,*r]
        if run(args,True)!=run(args,False): bad+=1; print("DIFF",rnd,os.path.basename(a),r)
# getclass: first class per apk from listclass
for a in apks[:30]:
    rc,out=run(["listclass",a],False); cls=out.split(b"\n")[len(out.split(b"\n"))//2].decode().strip()
    if not cls: continue
    for _ in range(2):
        if run(["getclass",a,cls],True)!=run(["getclass",a,cls],False): bad+=1; print("DIFF getclass",a,cls)
print("pairs",len(pairs)*2,"mismatches",bad)
