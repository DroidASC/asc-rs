#!/usr/bin/env python3
"""Compare `droidasc resources APK` with `aapt2 dump resources APK`.

usage: compare.py [--aapt2 PATH] [--droidasc PATH] [--jobs N] [--examples FILE] APK_OR_DIR...

For every APK, both tools dump the whole resource table and the dumps are
compared per resource id: name, the set of configurations, and each
configuration's value after normalizing the two notations (aapt2 prints
`16.000000dp`, droidasc `16dp`; aapt2 prints bags as `(style) size=3
parent=...`, droidasc as `{parent=@... k=v ...}`, and so on).

Prints one line per APK and a total; `--examples` writes up to 20 examples
of every difference kind per APK.
"""
import argparse, concurrent.futures as cf, os, re, subprocess, sys
from collections import Counter, defaultdict

RES_LINE = re.compile(r"^    resource (0x[0-9a-f]{8}) (\S+)(.*)$")
STAGED = re.compile(r"STAGED_ID=(0x[0-9a-f]{8})")
# Attr definition metadata, which aapt2 leaves out of an attr's `size`.
ATTR_META = {"^type", "^min", "^max", "^l10n"}
VAL_LINE = re.compile(r"^      \(([^)]*)\) (.*)$")
OURS_LINE = re.compile(r"^(0x[0-9a-f]{8}) (\S+) (?:\[([^\]]*)\] )?(.*)$")
NUM = re.compile(r"^(-?[0-9.]+(?:e[-+]?\d+)?)(dp|sp|px|pt|in|mm|%p|%)?$")


def parse_aapt2(text):
    """({id: (name, [(config, value)])}, staged ids); multi-line strings are re-joined."""
    out, cur, last, staged = {}, None, None, set()
    # The dump ends with a newline; a blank line anywhere else is part of a string.
    for line in text.rstrip("\n").split("\n"):
        m = RES_LINE.match(line)
        if m:
            staged.update(STAGED.findall(m.group(3)))
            cur = out.setdefault(m.group(1), (m.group(2), []))
            last = None
            continue
        if cur is None:
            continue
        if last is not None and open_string(last[1]):
            # Continuation of a string with newlines; aapt2 indents it by 6.
            last[1] += "\n" + (line[6:] if line.startswith("      ") else line)
            continue
        m = VAL_LINE.match(line)
        if m:
            cur[1].append([m.group(1), m.group(2)])
            last = cur[1][-1]
        elif line.startswith("        ") or line.startswith("  type ") or line.startswith("Package "):
            continue  # bag item, next type or package header
        elif last is not None and (last[1].startswith('"') or last[1].startswith("(styled string) ")):
            # A line of a string that had a quote right before a newline.
            last[1] += "\n" + (line[6:] if line.startswith("      ") else line)
    return out, staged


def open_string(v):
    """Whether an aapt2 string value has not reached its closing quote yet."""
    if v.startswith("(styled string) "):
        return v.count('"') < 2
    return v.startswith('"') and (len(v) == 1 or not v.endswith('"'))


def parse_ours(text):
    out = {}
    for line in text.split("\n"):
        m = OURS_LINE.match(line)
        if m:
            rid, name, cfg, val = m.groups()
            out.setdefault(rid, (name, []))[1].append([cfg or "", val])
    return out


def unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def norm_ref(s):
    s = s.split(" (0x")[0].lstrip("@?")
    s = s.replace("android:0x", "0x")
    if ":" in s and not s.startswith("android:"):
        s = s.split(":", 1)[1]  # other packages: aapt2 omits the package
    return s.lower()


def bag_items(body):
    """Split `{parent=@x k="v w" k2=3}` into (parent, [keys])."""
    parent, keys, i = None, [], 0
    while i < len(body):
        while i < len(body) and body[i] == " ":
            i += 1
        j = body.find("=", i)
        if j < 0:
            break
        key = body[i:j]
        i = j + 1
        if i < len(body) and body[i] == '"':
            i += 1
            while i < len(body) and body[i] != '"':
                i += 2 if body[i] == "\\" else 1
            i += 1
        else:
            while i < len(body) and body[i] != " ":
                i += 1
        val = body[j + 1:i]
        if key == "parent":
            parent = norm_ref(val)
        else:
            keys.append(key)
    return parent, keys


def norm_num(s):
    m = NUM.match(s)
    if not m:
        return None
    try:
        v = float(m.group(1))
    except ValueError:
        return None
    return ("num", v, m.group(2) or "")


def norm_aapt2(v):
    if v.startswith("(file) "):
        return ("str", v[7:].rsplit(" type=", 1)[0])
    if v.startswith("(styled string) "):
        # Text only: drop the span list (` b:8,11`) after the closing quote.
        v = v[16:]
        return ("str", v[1:v.rfind('"')] if v.count('"') >= 2 else v[1:])
    if v.startswith('"'):
        return ("str", v[1:-1] if v.endswith('"') and len(v) > 1 else v[1:])
    if v == "(id)":
        return ("id",)
    m = re.match(r"^\((style|array|plurals|attr|styleable)\)(.*)$", v)
    if m:
        size = re.search(r"size=(\d+)", m.group(2))
        parent = re.search(r"parent=(\S+)", m.group(2))
        return ("bag", int(size.group(1)) if size else 0, norm_ref(parent.group(1)) if parent else None)
    if v in ("@null", "(null)"):
        return ("null",)
    if v == "(empty)":
        return ("empty",)
    if v[:1] in "@?":
        return ("ref", v[0], norm_ref(v))
    if v.startswith("#"):
        return ("color", int(v[1:], 16) & 0xFFFFFF if len(v) == 7 else int(v[1:], 16))
    if v in ("true", "false"):
        return ("bool", v == "true")
    if v.startswith("0x"):
        return ("num", float(int(v, 16)), "")
    return norm_num(v) or ("raw", v)


def norm_ours(v):
    if v.startswith('"'):
        return ("str", unescape(v[1:-1]))
    if v.startswith("{"):
        parent, keys = bag_items(v[1:-1])
        return ("bag", len([k for k in keys if k not in ATTR_META]), parent)
    if v == "@null":
        return ("null",)
    if v == "@empty":
        return ("empty",)
    if v[:1] in "@?":
        return ("ref", v[0], norm_ref(v))
    if v.startswith("#"):
        return ("color", int(v[1:], 16) & 0xFFFFFF if len(v) == 7 else int(v[1:], 16))
    if v in ("true", "false"):
        return ("bool", v == "true")
    if v.startswith("0x"):
        return ("num", float(int(v, 16)), "")
    return norm_num(v) or ("raw", v)


def same(a, b):
    if a == b:
        return True
    if a[0] == "id":
        return True  # `id` entries are placeholder values
    if a[0] == "num" and b[0] == "num" and a[2] == b[2]:
        close = lambda x, y: abs(x - y) <= max(1e-3, abs(x) * 1e-5)
        # aapt2 prints the 24-bit mantissa unsigned: -3dp shows as 16777213dp.
        signed = [a[1]] + ([a[1] - (1 << 24) * m for m in (1, 2**-7, 2**-15, 2**-23)] if a[2] else [])
        if a[2] in ("%", "%p"):
            # aapt2 prints the raw fraction (0.8%); droidasc as written (80%).
            return any(close(x * 100, b[1]) or close(x, b[1]) for x in signed)
        return any(close(x, b[1]) for x in signed)
    # aapt2 shows a 6-digit color for RGB8 but keeps the alpha for ARGB8.
    if a[0] == b[0] == "color":
        return (a[1] & 0xFFFFFF) == (b[1] & 0xFFFFFF)
    # Bags: aapt2 counts attr enum/flag symbols in `size`, plurals quantities and
    # style/array entries; parents must agree when both name one.
    if a[0] == b[0] == "bag":
        return a[1] == b[1] and (a[2] is None or b[2] is None or a[2] == b[2])
    if a[0] == "empty" and b[0] == "null":
        return True
    return False


def compare(apk, aapt2, droidasc):
    a = subprocess.run([aapt2, "dump", "resources", apk], capture_output=True)
    o = subprocess.run([droidasc, "--no-cache", "resources", apk], capture_output=True)
    stats = Counter()
    ex = defaultdict(list)
    if a.returncode != 0:
        stats["aapt2_failed"] += 1
        ex["aapt2_failed"].append(a.stderr.decode(errors="replace").strip()[:200])
    if o.returncode != 0:
        stats["droidasc_failed"] += 1
        ex["droidasc_failed"].append(o.stderr.decode(errors="replace").strip()[:200])
    # Bytes, not text mode: universal newlines would turn a "\r" inside a string into "\n".
    (A, staged), O = parse_aapt2(a.stdout.decode(errors="replace")), parse_ours(o.stdout.decode(errors="replace"))
    stats["ids"] = len(A)
    stats["values"] = sum(len(v[1]) for v in A.values())

    def note(kind, msg):
        stats[kind] += 1
        if len(ex[kind]) < 20:
            ex[kind].append(msg)

    for rid in sorted(set(A) | set(O)):
        # aapt2 folds a staged id's values into the finalized resource and lists
        # it only partially; droidasc shows the staged chunk as stored.
        if rid in staged:
            stats["staged_skipped"] += 1
            continue
        if rid not in O:
            note("missing_id", f"{rid} {A[rid][0]}")
            continue
        if rid not in A:
            note("extra_id", f"{rid} {O[rid][0]}")
            continue
        (an, av), (on, ov) = A[rid], O[rid]
        if an != on.split(":", 1)[-1]:
            note("name", f"{rid} aapt2={an} ours={on}")
        acfg = Counter(c for c, _ in av)
        ocfg = Counter(c for c, _ in ov)
        if acfg != ocfg:
            note("configs", f"{rid} {an} aapt2={sorted(acfg.elements())} ours={sorted(ocfg.elements())}")
            continue
        for (c, x), (_, y) in zip(sorted(av, key=lambda t: t[0]), sorted(ov, key=lambda t: t[0])):
            nx, ny = norm_aapt2(x), norm_ours(y)
            if not same(nx, ny):
                kind = "value_" + nx[0]
                note(kind, f"{rid} {an} ({c}) aapt2={x[:160]!r} ours={y[:160]!r}")
    return apk, stats, ex


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aapt2", default=os.path.expanduser("~/Android/Sdk/build-tools/37.0.0/aapt2"))
    ap.add_argument("--droidasc", default="target/release/droidasc")
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--examples")
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args()
    apks = []
    for p in args.paths:
        if os.path.isdir(p):
            apks += sorted(os.path.join(p, f) for f in os.listdir(p) if f.endswith(".apk"))
        else:
            apks.append(p)
    total = Counter()
    ex_out = open(args.examples, "w") if args.examples else None
    with cf.ThreadPoolExecutor(args.jobs) as pool:
        for apk, stats, ex in pool.map(lambda a: compare(a, args.aapt2, args.droidasc), apks):
            total += stats
            diffs = {k: v for k, v in stats.items() if k not in ("ids", "values", "staged_skipped")}
            print(f"{os.path.basename(apk)}: ids={stats['ids']} values={stats['values']} " + (" ".join(f"{k}={v}" for k, v in sorted(diffs.items())) or "OK"), flush=True)
            if ex_out and ex:
                ex_out.write(f"== {apk}\n")
                for k, lines in sorted(ex.items()):
                    for l in lines:
                        ex_out.write(f"  [{k}] {l}\n")
    diffs = {k: v for k, v in total.items() if k not in ("ids", "values", "staged_skipped")}
    print(f"TOTAL {len(apks)} APKs: ids={total['ids']} values={total['values']} " + (" ".join(f"{k}={v}" for k, v in sorted(diffs.items())) or "no differences"))


if __name__ == "__main__":
    main()
