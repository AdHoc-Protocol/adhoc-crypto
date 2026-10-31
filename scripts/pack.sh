#!/usr/bin/env bash
# Lays out/natives/<os>/<arch>/ as out/adhoc-crypto/<rid>/, the folders the other languages look in ( lib/native/<rid>/ ), and zips it.
#
#   pack.sh
#
# The languages other than Java get the library from here. Java gets the jar of jar.sh, with the same files inside.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/out/adhoc-crypto
rm -rf "$OUT" "$OUT.zip"
for dir in "$ROOT"/out/natives/*/*/; do
  arch=$(basename "$dir")
  os=$(basename "$(dirname "$dir")")
  case $os in
    win) o=win ;;
    darwin) o=osx ;;
    linux | linux-musl | freebsd) o=$os ;;
    *) echo "unknown os $os" >&2; exit 2 ;;
  esac
  case $arch in
    amd64 | x86_64) a=x64 ;;
    aarch64) a=arm64 ;;
    x86 | i386) a=x86 ;;
    arm | riscv64) a=$arch ;;
    *) echo "unknown arch $arch" >&2; exit 2 ;;
  esac
  mkdir -p "$OUT/$o-$a"
  cp "$dir"libadhoc-crypto-* "$OUT/$o-$a/"
done
"$JAVA_HOME/bin/jar" --create --no-manifest --file "$OUT.zip" -C "$OUT" .
ls -la "$OUT.zip"
find "$OUT" -type f | sed "s#$OUT/##" | sort
