#!/usr/bin/env python3
"""Inventory of a corpus directory (the APKs themselves are not in the repository).

usage: manifest.py DROIDASC DIR [DIR...] > corpus.tsv
One row per APK: file, package, versionName, versionCode, bytes, sha256. Package and
versions come from the first `droidasc manifest-summary` line; `-` when an APK has no
manifest droidasc can read.
"""
import concurrent.futures as cf, hashlib, os, re, subprocess, sys

B, DIRS = sys.argv[1], sys.argv[2:]


def row(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    out = subprocess.run([B, "--no-cache", "manifest-summary", path], capture_output=True, text=True,
                         env=dict(os.environ, DROIDASC_DAEMON="off")).stdout
    first = out.splitlines()[0] if out else ""
    pkg = re.match(r"package (\S+)", first)
    vc = re.search(r"versionCode=(\S+)", first)
    vn = re.search(r"versionName=(\S+)", first)
    rel = os.path.join(os.path.basename(os.path.dirname(path)), os.path.basename(path))
    return "\t".join([rel, pkg.group(1) if pkg else "-", vn.group(1) if vn else "-", vc.group(1) if vc else "-",
                      str(os.path.getsize(path)), h.hexdigest()])


apks = sorted(os.path.join(d, f) for d in DIRS for f in os.listdir(d) if f.endswith(".apk"))
print("file\tpackage\tversionName\tversionCode\tbytes\tsha256")
with cf.ThreadPoolExecutor(8) as ex:
    for r in ex.map(row, apks):
        print(r)
