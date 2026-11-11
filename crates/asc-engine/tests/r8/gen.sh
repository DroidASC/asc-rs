#!/bin/sh
# Regenerates classes.dex and mapping.txt with R8 (Android build-tools).
# Usage: gen.sh <build-tools-dir> <android.jar>
set -eu
cd "$(dirname "$0")"
bt=${1:?build-tools dir, e.g. $ANDROID_HOME/build-tools/37.0.0}
android_jar=${2:?android.jar, e.g. $ANDROID_HOME/platforms/android-36/android.jar}
work=$(mktemp -d "${TMPDIR:-$HOME/.cache}/asc-r8.XXXXXX")
trap 'rm -rf "$work"' EXIT
javac --release 8 -g -d "$work/classes" $(find src -name '*.java')
(cd "$work/classes" && jar cf ../in.jar .)
java -cp "$bt/lib/d8.jar" com.android.tools.r8.R8 --release --min-api 21 --lib "$android_jar" \
    --pg-conf rules.pro --pg-map-output mapping.txt --output "$work" "$work/in.jar"
cp "$work/classes.dex" classes.dex
