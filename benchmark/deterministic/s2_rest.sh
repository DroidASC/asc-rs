#!/bin/zsh
# rust_ASC CLI pool and dexsql over the S2 corpus, 3 trials (dexsql: probe shapes once, then 3 trials of the fastest).
# Layout: $ASC_EVAL (default ~/asc-eval) holds src/ (this repo, built), bin/, apks/, rust_ASC/, results/;
# scratch caches go to $BENCH_TMP (default /private/tmp/asc-bench). Scripts are found next to this file.
H=${0:A:h}
cd ${ASC_EVAL:-$HOME/asc-eval}
T0=${BENCH_TMP:-/private/tmp/asc-bench}
R=results/round2
for k in 1 2 3; do python3 $H/s2.py rust rust_ASC/target/release/rust_ASC $R/s2-rust-cli.t$k.json 16 2; done
for shape in "1 16 2" "1 32 1" "16 8 4" "64 4 8" "64 14 2"; do
  set -- ${=shape}; python3 $H/dexsql_s2.py bin/dexsql $R/s2-dexsql-probe-K$1-P$2-T$3.json $1 $2 $3
done
best=$(python3 -c "
import glob, json
r = [json.load(open(p)) for p in glob.glob('$R/s2-dexsql-probe-*.json')]
b = min((x for x in r if not x['failed'] or x['K'] == 1), key=lambda x: x['ms'])
print(b['K'], b['P'], b['T'])")
echo "dexsql best shape: $best"
for k in 1 2 3; do set -- ${=best}; python3 $H/dexsql_s2.py bin/dexsql $R/s2-dexsql.t$k.json $1 $2 $3; done
