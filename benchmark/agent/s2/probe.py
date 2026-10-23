import concurrent.futures as cf, os, subprocess, sys
B, D = sys.argv[1:3]; rules = sys.argv[3:]
apks = sorted(f for f in os.listdir(D) if f.endswith(".apk"))
def one(a):
    r = subprocess.run([B, "--no-cache", "findrefs", os.path.join(D, a), "rules", *rules, "--threads", "2"], capture_output=True, text=True)
    return {l.split(" | ")[0] for l in r.stdout.splitlines() if l and not l.startswith("#")}
cnt = [0] * len(rules)
with cf.ThreadPoolExecutor(16) as ex:
    for s in ex.map(one, apks):
        for i in range(len(rules)):
            cnt[i] += f"r{i+1}" in s
for r, c in zip(rules, cnt): print(c, r)
