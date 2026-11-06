#!/usr/bin/env bash
# Lays out/adhoc-crypto/<rid>/ and out/natives/android/<abi>/ as runtimes/<rid>/native/ of out/AdHoc.Crypto.<version>.<number>.nupkg.
#
#   nupkg.sh <version> [number]         the version names the file of the library, the number counts the builds of it: 0 by default
#
# OUT is the folder of the layout, out/ by default. The package has the native library and nothing else: C# has its code in lib.
set -euo pipefail
VERSION=$1
NUMBER=${2:-0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$ROOT/out}
PACK=$OUT/nupkg
ID=AdHoc.Crypto
rm -rf "$PACK" "$OUT/$ID".*.nupkg
FILES=
# Each file by its name: `runtimes/**` keeps its folder on Windows and drops it on Linux.
lay() {
  mkdir -p "$PACK/runtimes/$1/native"
  for file in "$2"libadhoc-crypto-*; do
    cp "$file" "$PACK/runtimes/$1/native/"
    FILES="$FILES    <file src=\"runtimes/$1/native/$(basename "$file")\" target=\"runtimes/$1/native/\" />
"
  done
}
for dir in "$OUT"/adhoc-crypto/*/; do
  lay "$(basename "$dir")" "$dir"
done
for dir in "$OUT"/natives/android/*/; do
  [ -d "$dir" ] || continue # a local build has no Android
  case $(basename "$dir") in
    arm64-v8a) rid=android-arm64 ;;
    armeabi-v7a) rid=android-arm ;;
    x86_64) rid=android-x64 ;;
    x86) rid=android-x86 ;;
    *) echo "unknown abi $dir" >&2; exit 2 ;;
  esac
  lay "$rid" "$dir"
done
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$PACK/"
cat > "$PACK/$ID.nuspec" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>$ID</id>
    <version>$VERSION.$NUMBER</version>
    <authors>Chikirev Sirguy, Unirail Group</authors>
    <license type="file">LICENSE</license>
    <projectUrl>https://github.com/AdHoc-Protocol/adhoc-crypto</projectUrl>
    <description>The native library of the AdHoc runtime: BoringSSL and the chain of TLS, WebSocket frames and Noise, for every platform BoringSSL builds for.</description>
  </metadata>
  <files>
    <file src="LICENSE" />
    <file src="NOTICE" />
$FILES  </files>
</package>
EOF
cat > "$PACK/pack.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <NoBuild>true</NoBuild>
    <IncludeBuildOutput>false</IncludeBuildOutput>
    <NuspecFile>$ID.nuspec</NuspecFile>
  </PropertyGroup>
</Project>
EOF
dotnet pack "$PACK/pack.csproj" --nologo -v q -o "$OUT"
rm -rf "$PACK"
ls -la "$OUT/$ID".*.nupkg
