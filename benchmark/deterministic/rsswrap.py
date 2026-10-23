#!/usr/bin/env python3
"""usage: rsswrap.py OUT.txt CMD... — run CMD, write the peak summed RSS (MB) of its process tree to OUT.txt."""
import os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import TreeSampler
p = subprocess.Popen(sys.argv[2:])
s = TreeSampler([p.pid])
rc = p.wait()
open(sys.argv[1], "w").write("%d\n" % s.finish())
sys.exit(rc)
