#!/bin/bash
# no-fsync (round 2): cached results equal --no-cache ones when the cache is fresh, when it
# predates this boot (verified once), and when an L1 file is damaged (dropped, rewritten).
# usage: nofsync_check.sh BASE NEW APK CACHE_DIR   (Linux and macOS)
B=$1 N=$2 A=$3 D=$4
export DROIDASC_DAEMON=off
rm -rf $D; mkdir -p $D; export DROIDASC_CACHE_TIERS=dex,derived
h() { "$@" | sort | cksum; }
# mtime two days back: "written before this boot"
age() { python3 -c 'import os, sys, time; t = time.time() - 172800; [os.utime(p, (t, t)) for p in sys.argv[1:]]' "$@"; }
for q in "method exec --class java.lang.Runtime" "string ttdownloaderClickId" "type Ldalvik/system/DexClassLoader;" 'field SDK_INT --class android.os.Build$VERSION' "string http://"; do
  ref=$(h $B --no-cache findrefs $A $q)
  c1=$(h $N --cache-dir $D findrefs $A $q); c2=$(h $N --cache-dir $D findrefs $A $q)
  find $D -type f -exec python3 -c 'import os, sys, time; t = time.time() - 172800; [os.utime(p, (t, t)) for p in sys.argv[1:]]' {} +
  c3=$(h $N --cache-dir $D findrefs $A $q)
  rows=$($B --no-cache findrefs $A $q | wc -l)
  echo "$q: rows=$rows $([ "$ref" = "$c1" ] && [ "$ref" = "$c2" ] && [ "$ref" = "$c3" ] && echo same || echo "DIFF $ref $c1 $c2 $c3")"
done
f=$(find $D -type f -size +4M -not -path '*derived*' | head -1)
printf '\0\0\0\0\0\0\0\0' | dd of=$f bs=1 seek=4096 conv=notrunc 2>/dev/null; age $f
q="string ttdownloaderClickId"
[ "$(h $N --cache-dir $D findrefs $A $q)" = "$(h $B --no-cache findrefs $A $q)" ] && echo "damaged L1 $(basename $f): same result; file now $([ -e $f ] && echo "rewritten, $(wc -c < $f) bytes" || echo removed)"
rm -rf $D
