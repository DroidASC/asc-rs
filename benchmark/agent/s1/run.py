#!/usr/bin/env python3
"""Real-agent eval: grok headless with only one MCP server (droidasc or dexsql).

usage: run.py ROOT TAG REPS CONC [tool ...]   (ROOT has ws-<tool>/, apks/douyin.apk, runs/)
"""
import concurrent.futures as cf, json, os, runpy, subprocess, sys, time
ROOT, TAG, REPS, CONC = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
FILES = "--files" in sys.argv
TOOLS = [a for a in sys.argv[5:] if not a.startswith("--")] or ["droidasc", "dexsql"]
# dexsql-release benchmarks/agent-audit/harness (its SCENARIOS are imported, not copied).
H = os.environ.get("HARNESS") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dexsql-release/benchmarks/agent-audit/harness")
sys.path.insert(0, H)
SC = runpy.run_path(os.path.join(H, "rasc_replay.py"), run_name="x")["SCENARIOS"]
SC.pop("class_inventory", None)
APK = os.path.join(ROOT, "apks/douyin.apk")
# --files: read_file / grep / list_dir allowed, but only inside the workspace (strict sandbox),
# and never Grok's own session store (earlier runs' answers live there).
FILE_TOOLS = ("read_file", "grep", "list_dir")
HOME_GROK = os.path.expanduser("~/.grok")
if sys.platform == "darwin":
    # grok's strict profile refuses to start on this Mac (docker.sock symlink), so the
    # workspace lives outside /Users and every user path is denied to the file tools.
    SANDBOX = [arg for root in ("/Users", "/Volumes") for tool in ("Read", "Grep") for arg in ("--deny", f"{tool}({root}/**)")]
else:
    SANDBOX = ["--sandbox", "strict", "--deny", f"Read({HOME_GROK}/**)", "--deny", f"Grep({HOME_GROK}/**)"]
DIS = ("run_terminal_command,read_file,search_replace,list_dir,grep,kill_command_or_subagent,todo_write,"
       "get_command_or_subagent_output,scheduler_create,scheduler_delete,scheduler_list,monitor,workflow,"
       "enter_plan_mode,exit_plan_mode,ask_user_question,send_feedback,image_gen,image_edit,image_to_video,"
       "reference_to_video,write")

def hint(sc):
    step = [a for a in sc["steps"][0] if not a.startswith("/") and a != "--threads" and not a.isdigit()][1:]
    if len(step) < 2:
        return None
    kind, rest = step[0], step[1:]
    if kind == "string": return f'the string "{rest[0]}"'
    if kind == "type": return f"the type {rest[0]}"
    if kind == "method":
        cls = rest[rest.index("--class") + 1] if "--class" in rest else None
        return f"the method {rest[0]}" + (f" (class {cls})" if cls else "")
    return " ".join(step)

def prompt(name, sc, tool):
    apk = os.path.join(ROOT, f"ws-{tool}", "douyin.apk") if FILES else APK
    p = f"APK: {apk}\nGoal: {sc['intent']}\n"
    if name == "dynamic_loading_census":
        p += "Starting point: references to DexClassLoader, System.load and Runtime.exec.\n"
    elif (h := hint(sc)):
        p += f"Starting point: {h}.\n"
    return p + ("Use the available APK analysis tools. Answer the goal concisely and quote the code evidence "
                "(class / method names, strings, instructions) you relied on.")

OUT = lambda tool, name, rep: os.path.join(ROOT, "runs", TAG, "%s.%s.%d.ndjson" % (tool, name, rep))
TIMEOUT = 1200
def CMD(tool, name):
    dis = ",".join(t for t in DIS.split(",") if not (FILES and t in FILE_TOOLS))
    return [os.environ.get("GROK", "grok"), "-p", prompt(name, SC[name], tool), "--trust", *(SANDBOX if FILES else []), "--disallowed-tools", dis,
            "--no-subagents", "--no-plan", "--disable-web-search", "--always-approve", "--output-format", "streaming-json"]

def rate_limited(path):
    with open(path) as f:
        return any('"type":"error"' in l.replace(" ", "") and "rate_limit" in l for l in f)

def run(job):
    tool, name, rep = job
    out = OUT(tool, name, rep)
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return
    for attempt in range(8):
        t = time.time()
        with open(out + ".tmp", "w") as f:
            try:
                subprocess.run(CMD(tool, name), cwd=os.path.join(ROOT, "ws-" + tool), stdout=f, stderr=subprocess.DEVNULL, timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                f.write(json.dumps({"type": "timeout"}) + "\n")
        if not rate_limited(out + ".tmp"):
            break
        print("rate limited %s %s %d, retry %d" % (tool, name, rep, attempt + 1), flush=True)
        time.sleep(60 * (attempt + 1))
    with open(out + ".tmp", "a") as f:
        f.write(json.dumps({"type": "wall", "seconds": time.time() - t, "attempts": attempt + 1}) + "\n")
    os.rename(out + ".tmp", out)
    print("done %s %s %d %.0fs" % (tool, name, rep, time.time() - t), flush=True)

os.makedirs(os.path.join(ROOT, "runs", TAG), exist_ok=True)
jobs = [(t, n, r) for r in range(1, REPS + 1) for n in SC for t in TOOLS]
with cf.ThreadPoolExecutor(CONC) as ex:
    for f in [ex.submit(run, j) for j in jobs]:
        try: f.result()
        except Exception as e: print("ERR", e, flush=True)
