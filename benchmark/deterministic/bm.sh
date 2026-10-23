#!/bin/zsh
# big-machine validation: old (src-r2) vs new (src-bm), alternating per trial.
# Layout: $ASC_EVAL (default ~/asc-eval) holds src/ (this repo, built), bin/, apks/, rust_ASC/, results/;
# scratch caches go to $BENCH_TMP (default /private/tmp/asc-bench). Scripts are found next to this file.
H=${0:A:h}
cd ${ASC_EVAL:-$HOME/asc-eval}
T0=${BENCH_TMP:-/private/tmp/asc-bench}
R=results/round2-bm; C=$T0/cache; N=${TRIALS:-3}
mkdir -p $R $T0
export DROIDASC_DAEMON=off
OLD=src-r2/target/release/droidasc; NEW=src-bm/target/release/droidasc
S2() { zsh $H/guard.sh 40000 python3 $H/s2.py "$@" 2>&1 | grep -v "^guard peak" | sed "s/^/  /"; }
L() { echo "  load $(sysctl -n vm.loadavg)"; }
# 1. AUTO threads, mcprules N=1/4/8/16 cold + warm
for n in 1 4 8 16; do
  echo "== auto N=$n"; L
  for k in $(seq $N); do for v in old new; do B=$([ $v = new ] && echo $NEW || echo $OLD)
    rm -rf $C; AUTO=1 S2 mcprules $B $R/auto-$v-n$n-cold.t$k.json $n -- --cache-dir $C
    AUTO=1 S2 mcprules $B $R/auto-$v-n$n-warm.t$k.json $n -- --cache-dir $C
  done; done
done
# 2. N=16 fixed threads (new): long-tail check
for t in 2 4 8 32; do
  echo "== N=16 THREADS=$t"; L
  for k in $(seq $N); do
    rm -rf $C; THREADS=$t S2 mcprules $NEW $R/fixed-t$t-n16-cold.t$k.json 16 -- --cache-dir $C
    THREADS=$t S2 mcprules $NEW $R/fixed-t$t-n16-warm.t$k.json 16 -- --cache-dir $C
  done
done
# 3. disk cap: one cold single-server sweep, default budget, then cache stats and warm
for v in old new; do B=$([ $v = new ] && echo $NEW || echo $OLD)
  echo "== disk cap $v"; L
  rm -rf $C; AUTO=1 S2 mcprules $B $R/cap-$v-cold.json 1 -- --cache-dir $C
  echo "  $($B --cache-dir $C cache stats 2>&1 | tr '\n' ' ')"; echo "  du $(du -sm $C | cut -f1) MB"
  for k in $(seq $N); do AUTO=1 S2 mcprules $B $R/cap-$v-warm.t$k.json 1 -- --cache-dir $C; done
done
rm -rf $C
# 4. S1 regression
D=apks/k80/com.ss.android.ugc.aweme.apk
for v in old new; do B=$([ $v = new ] && echo $NEW || echo $OLD)
  echo "== s1 $v"; L
  python3 $H/s1.py asc-cli $B $D 5 $R/s1-$v-cli-nocache.json --no-cache 2>&1 | tail -2 | sed "s/^/  /"
  rm -rf $C; python3 $H/s1.py asc-mcp-hot $B $D 5 $R/s1-$v-mcp-hot.json --cache-dir $C 2>&1 | tail -2 | sed "s/^/  /"
done
rm -rf $C
echo DONE
