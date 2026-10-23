#!/usr/bin/env python3
"""S2 real-agent eval: one exposure question over a directory of APKs.

usage: run.py ROOT TAG REPS CONC tool ...   (ROOT has ws-<tool>/k80/*.apk with MCP configured, runs/)
The file tools (list_dir / read_file / grep) stay on so the agent can see the directory; the
workspace lives outside /Users and every user path is denied to them.
"""
import concurrent.futures as cf, json, os, runpy, subprocess, sys, time
ROOT, TAG, REPS, CONC = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
TOOLS = sys.argv[5:]
GOALS = runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "goals.py"))["GOALS"]
SANDBOX = [a for root in ("/Users", "/Volumes") for t in ("Read", "Grep") for a in ("--deny", "%s(%s/**)" % (t, root))]
DIS = ("run_terminal_command,search_replace,kill_command_or_subagent,todo_write,"
       "get_command_or_subagent_output,scheduler_create,scheduler_delete,scheduler_list,monitor,workflow,"
       "enter_plan_mode,exit_plan_mode,ask_user_question,send_feedback,image_gen,image_edit,image_to_video,"
       "reference_to_video,write")

def prompt(goal, tool):
    d = os.path.join(ROOT, "ws-" + tool, "k80")
    n = sum(f.endswith(".apk") for f in os.listdir(d))
    return ("APK directory: %s (%d APKs pulled from one phone)\nGoal: %s\n"
            "Use the available APK analysis tools. Check every APK in the directory. End your answer with one line per "
            "matching APK in the form `APK: <file name without .apk>`, each with the class / method you found the call in."
            % (d, n, goal["intent"]))

OUT = lambda tool, name, rep: os.path.join(ROOT, "runs", TAG, "%s.%s.%d.ndjson" % (tool, name, rep))
TIMEOUT = 2400
def CMD(tool, name):
    return [os.environ.get("GROK", "grok"), "-p", prompt(GOALS[name], tool), "--trust", *SANDBOX, "--disallowed-tools", DIS,
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
jobs = [(t, n, r) for r in range(1, REPS + 1) for n in GOALS for t in TOOLS]
with cf.ThreadPoolExecutor(CONC) as ex:
    for f in [ex.submit(run, j) for j in jobs]:
        try: f.result()
        except Exception as e: print("ERR", e, flush=True)
