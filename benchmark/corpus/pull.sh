#!/bin/zsh
# pull.sh SERIAL NAME: every package (system + third-party), base APK only
A=~/Library/Android/sdk/platform-tools/adb; s=$1; out=~/asc-eval/apks/$2; mkdir -p $out
$A -s $s shell pm list packages -f | sed "s/^package://" | while IFS= read -r line; do
  src="${line%=*}"; pkg="${line##*=}"; f="$out/$pkg.apk"
  [ -s "$f" ] || $A -s $s pull "$src" "$f" >/dev/null 2>&1 || { rm -f "$f"; echo "FAIL $pkg"; }
done
echo "$2: $(ls $out | wc -l) apks, $(du -sh $out | cut -f1)"
