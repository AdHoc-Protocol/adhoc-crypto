#!/usr/bin/env bash
# Puts out/natives/android/** into out/adhoc-crypto.aar, as zstd-jni does: jni/<abi>/, and the version the classes that load it read.
set -euo pipefail
VERSION=$1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
AAR=$ROOT/out/aar
rm -rf "$AAR" "$ROOT/out/adhoc-crypto.aar"
mkdir -p "$AAR/classes/org/unirail/crypto" "$AAR/jni"
printf '%s\n' "$VERSION" > "$AAR/classes/org/unirail/crypto/version"
"$JAVA_HOME/bin/jar" --create --no-manifest --file "$AAR/classes.jar" -C "$AAR/classes" .
rm -rf "$AAR/classes"
cp -r "$ROOT"/out/natives/android/* "$AAR/jni/"
printf '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.unirail.crypto">\n    <uses-sdk android:minSdkVersion="24"/>\n</manifest>\n' > "$AAR/AndroidManifest.xml"
: > "$AAR/R.txt"
"$JAVA_HOME/bin/jar" --create --no-manifest --file "$ROOT/out/adhoc-crypto.aar" -C "$AAR" .
"$JAVA_HOME/bin/jar" --list --file "$ROOT/out/adhoc-crypto.aar"
ls -la "$ROOT/out/adhoc-crypto.aar"
