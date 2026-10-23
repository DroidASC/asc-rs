#!/bin/zsh
# usage: guard.sh LIMIT_MB CMD... — run CMD, kill its tree when any droidasc exceeds LIMIT_MB RSS; print peak.
lim=$1; shift
"$@" & pid=$!
peak=0; t0=$SECONDS
while kill -0 $pid 2>/dev/null; do
  r=$(ps -axo rss=,comm= | awk '/droidasc/ {if ($1 > m) m = $1} END {print int(m / 1024)}')
  (( r > peak )) && peak=$r
  if (( r > lim )); then echo "GUARD: droidasc RSS ${r} MB > ${lim} after $((SECONDS - t0)) s, killing"; pkill -P $pid; kill $pid; pkill -f "asc-bench/cache --threads"; break; fi
  sleep 2
done
wait $pid 2>/dev/null
echo "guard peak droidasc RSS ${peak} MB, $((SECONDS - t0)) s"
