#!/usr/bin/env python3
"""Compare droidasc findrefs with the Python reference by what they find, not how
they print it.

usage: semantic.py [--upstream ../ASC] [--droidasc target/release/droidasc]
                   [--queries FILE] APK

Both outputs are parsed into a set of (dex, Lcls;->name, matched) rows, `matched` the
matched values in order; the line formats differ on purpose (droidasc adds signatures
and field types, quotes strings, uses `, ` and `|` columns). A query is a line of
findrefs arguments (`string http`, `method exec --class java.lang.Runtime`); without
--queries a default audit-style set runs. Exits 1 on any difference.
"""
import argparse, json, re, shlex, subprocess, sys

DEFAULT_QUERIES = [
    "string http",
    "string password",
    "type Landroid/webkit/WebView;",
    "type Ljava/lang/String;",
    "method exec --class java.lang.Runtime",
    "method loadUrl",
    "method onCreate",
    "field SDK_INT",
    "extends java.lang.Object",
]
# A row starts with its DEX name; Python continues a multi-line string on the next lines.
ROW_START = re.compile(r"^classes\d*\.dex(?:!\S+)? \| ")
PY_MEMBER = re.compile(r"^(\S+) \| (\S+) \| matched=\((.*)\)$", re.S)
PY_RELATION = re.compile(r"^(\S+) \| (\S+) (extends|implements) (\S+)$")


def records(text):
    """Lines of `text` regrouped into rows (continuation lines joined back)."""
    rows = []
    # Only the last row's line terminator: a matched string may itself end in "\n".
    for line in text.removesuffix("\n").split("\n"):
        if ROW_START.match(line) or not rows:
            rows.append(line)
        else:
            rows[-1] += "\n" + line
    return [r for r in rows if r]


def parse_upstream(text):
    out = set()
    for r in records(text):
        if m := PY_RELATION.match(r):
            out.add((m[1], m[2], (f"{m[3]} {m[4]}",)))
        elif m := PY_MEMBER.match(r):
            # Python joins with "; ", so keep its joined form: our side re-joins the same way.
            out.add((m[1], m[2], (m[3],)))
        else:
            raise ValueError(f"unparsed upstream row: {r[:120]!r}")
    return out


def matched_items(col):
    """`"a", Lx;->m()V, "b"` -> ["a", "Lx;->m()V", "b"]: strings are JSON, symbols
    run to the next `, ` (descriptors never hold one)."""
    items, i, dec = [], 0, json.JSONDecoder()
    while i < len(col):
        if col[i] == '"':
            s, i = dec.raw_decode(col, i)
        else:
            j = col.find(", ", i)
            j = len(col) if j < 0 else j
            s, i = col[i:j], j
        items.append(s)
        if col.startswith(", ", i):
            i += 2
    return items


def bare(member):
    """`Lcls;->name(params)ret` / `Lcls;->name:type` -> `Lcls;->name` (what Python prints)."""
    if "->" not in member:
        return member
    cls, rest = member.split("->", 1)
    return cls + "->" + re.split(r"[(:]", rest, maxsplit=1)[0]


def parse_ours(text, kind):
    out = set()
    for r in records(text):
        dex, subject, col = r.split(" | ", 2)
        if kind in ("extends", "impl"):
            out.add((dex, subject, (col,)))
            continue
        items = matched_items(col)
        if kind in ("method", "field"):
            items = [bare(s) for s in items]
        out.add((dex, bare(subject), ("; ".join(items),)))
    return out


def run(cmd, cwd=None):
    p = subprocess.run(cmd, capture_output=True, cwd=cwd)
    if p.returncode not in (0, 2):
        raise RuntimeError(f"{cmd[0]} failed: {p.stderr.decode(errors='replace')[:300]}")
    return p.stdout.decode("utf-8", errors="surrogateescape")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default="../ASC")
    ap.add_argument("--droidasc", default="target/release/droidasc")
    ap.add_argument("--queries")
    ap.add_argument("apk")
    args = ap.parse_args()
    queries = DEFAULT_QUERIES
    if args.queries:
        queries = [l.strip() for l in open(args.queries) if l.strip() and not l.startswith("#")]
    bad = 0
    for q in queries:
        argv = shlex.split(q)
        theirs = parse_upstream(run([sys.executable, "-m", "droidasc", "findrefs", args.apk, *argv], cwd=args.upstream))
        ours = parse_ours(run([args.droidasc, "--no-cache", "findrefs", args.apk, *argv]), argv[0])
        only_theirs, only_ours = theirs - ours, ours - theirs
        status = "ok" if not (only_theirs or only_ours) else "DIFF"
        print(f"{status:4} {q}: {len(ours)} rows (upstream {len(theirs)})")
        for tag, rows in (("upstream only", only_theirs), ("droidasc only", only_ours)):
            for row in sorted(rows)[:5]:
                print(f"     {tag}: {row}")
        bad += status != "ok"
    print(f"{bad} of {len(queries)} queries differ")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
