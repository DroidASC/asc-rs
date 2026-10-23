#!/bin/zsh
# S2 rule-set mode (all 8 rules per APK pass), serial, 3 trials.
# Layout: $ASC_EVAL (default ~/asc-eval) holds src/ (this repo, built), bin/, apks/, rust_ASC/, results/;
# scratch caches go to $BENCH_TMP (default /private/tmp/asc-bench). Scripts are found next to this file.
H=${0:A:h}
cd ${ASC_EVAL:-$HOME/asc-eval}
T0=${BENCH_TMP:-/private/tmp/asc-bench}
R=results/round2; C=$T0/cache; N=${TRIALS:-3}
S2() { zsh $H/guard.sh 24000 python3 $H/s2.py "$@" 2>&1 | grep -v "^guard peak" | sed "s/^/  /"; }
for v in ${=VERSIONS:-new old}; do
  B=$([ $v = new ] && echo src/target/release/droidasc || echo bin/droidasc-r1)
  echo "== $v"
  for k in $(seq $N); do S2 clirules $B $R/s2r-$v-cli-nocache.t$k.json 16 2 -- --no-cache; done
  for k in $(seq $N); do rm -rf $C; S2 clirules $B $R/s2r-$v-cli-cold.t$k.json 16 2 -- --cache-dir $C; done
  echo "  cache $(du -sm $C | cut -f1) MB"
  for k in $(seq $N); do S2 clirules $B $R/s2r-$v-cli-warm.t$k.json 16 2 -- --cache-dir $C; done
  for k in $(seq $N); do S2 mcprules $B $R/s2r-$v-mcp1-nocache.t$k.json 1 -- --no-cache; done
  for n in 1 4 8 16; do
    for k in $(seq $N); do rm -rf $C; S2 mcprules $B $R/s2r-$v-mcp$n-cold.t$k.json $n -- --cache-dir $C; done
    echo "  cache $(du -sm $C | cut -f1) MB"
    for k in $(seq $N); do S2 mcprules $B $R/s2r-$v-mcp$n-warm.t$k.json $n -- --cache-dir $C; done
  done
  rm -rf $C
done
