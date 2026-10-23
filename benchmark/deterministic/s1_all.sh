#!/bin/zsh
# Full S1 matrix, serial. Results in ~/asc-eval/results/round2/s1-*.json
set -e
# Layout: $ASC_EVAL (default ~/asc-eval) holds src/ (this repo, built), bin/, apks/, rust_ASC/, results/;
# scratch caches go to $BENCH_TMP (default /private/tmp/asc-bench). Scripts are found next to this file.
H=${0:A:h}
cd ${ASC_EVAL:-$HOME/asc-eval}
T0=${BENCH_TMP:-/private/tmp/asc-bench}
A=$PWD/apks/k80/com.ss.android.ugc.aweme.apk
R=results/round2; C=$T0; T=${TRIALS:-5}
S1() { python3 $H/s1.py "$@"; }
for v in new old; do
  B=$([ $v = new ] && echo src/target/release/droidasc || echo bin/droidasc-r1)
  S1 asc-cli $B $A $T $R/s1-$v-cli-nocache.json --no-cache
  rm -rf $C/s1-$v; S1 asc-cli $B $A 1 $C/warmup.json --cache-dir $C/s1-$v
  S1 asc-cli $B $A $T $R/s1-$v-cli-disk.json --cache-dir $C/s1-$v
  S1 asc-mcp $B $A $T $R/s1-$v-mcp-nocache.json --no-cache
  S1 asc-mcp $B $A $T $R/s1-$v-mcp-disk.json --cache-dir $C/s1-$v
  S1 asc-mcp-hot $B $A $T $R/s1-$v-mcp-hot.json --no-cache
  du -sm $C/s1-$v
  rm -rf $C/s1-$v
done
S1 rust-cli rust_ASC/target/release/rust_ASC $A $T $R/s1-rust-cli.json
S1 rust-mcp rust_ASC/target/release/rust_ASC $A $T $R/s1-rust-mcp.json
