#!/usr/bin/env bash
# Puts out/natives/** into out/adhoc-crypto-<version>.jar, in the layout of zstd-jni. The classes that load it are in the lib.
set -euo pipefail
VERSION=$1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLASSES=$ROOT/out/classes
rm -rf "$CLASSES"
mkdir -p "$CLASSES/org/unirail/crypto"
printf '%s
' "$VERSION" > "$CLASSES/org/unirail/crypto/version"
cp -r "$ROOT"/out/natives/* "$CLASSES/"
rm -rf "$CLASSES/android" # aar.sh: on Android a library comes in the APK
mkdir -p "$CLASSES/META-INF"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$CLASSES/META-INF/"
rm -f "$ROOT/out/adhoc-crypto-$VERSION.jar"
"$JAVA_HOME/bin/jar" --create --file "$ROOT/out/adhoc-crypto-$VERSION.jar" -C "$CLASSES" .
"$JAVA_HOME/bin/jar" --list --file "$ROOT/out/adhoc-crypto-$VERSION.jar" | grep -E 'adhoc-crypto'
ls -la "$ROOT/out/adhoc-crypto-$VERSION.jar"
