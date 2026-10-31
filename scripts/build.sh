#!/usr/bin/env bash
# Builds out/natives/<os>/<arch>/libadhoc-crypto-<version>.<ext> for the platform it runs on: BoringSSL, statically, and the
# JNI code around it. In gen/ BoringSSL has its assembly ready, so neither Perl nor Go is needed; on Windows x86-64 NASM is.
#
#   build.sh <os> <arch> <version>      os: win, linux, linux-musl, darwin, freebsd; arch: amd64, aarch64, x86_64, x86, i386, arm, riscv64
#
# JAVA_HOME gives jni.h. BORINGSSL names a checkout to use; without it the latest main is cloned: versions are not pinned.
# On Windows run it from a shell with vcvars64 applied, clang-cl, cmake, ninja and nasm on PATH.
set -euo pipefail
export MSYS_NO_PATHCONV=1

OS=$1 ARCH=$2 VERSION=$3
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$ROOT/out/work-$OS-$ARCH}
OUT=$ROOT/out/natives/$OS/$ARCH
mkdir -p "$WORK" "$OUT"

SRC=${BORINGSSL:-$WORK/boringssl}
if [ ! -d "$SRC" ]; then
  git clone --depth 1 --single-branch https://github.com/google/boringssl.git "$SRC"
fi
echo "BoringSSL $(git -C "$SRC" log -1 --format='%h %ad' --date=short 2>/dev/null || echo '(no git)')"

GEN=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF)
command -v ninja >/dev/null || GEN=(-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF)

case $OS in
  win)
    M=()
    [ "$ARCH" = x86 ] && M=(-m32)
    cmake -S "$SRC" -B "$WORK/b" "${GEN[@]}" -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DCMAKE_ASM_NASM_COMPILER=nasm "-DCMAKE_C_FLAGS=${M[*]:-}" "-DCMAKE_CXX_FLAGS=${M[*]:-}"
    cmake --build "$WORK/b" --target ssl crypto
    clang-cl "${M[@]}" /nologo /O2 /MT /W3 /DNDEBUG "/I$SRC/include" "/I$JAVA_HOME/include" "/I$JAVA_HOME/include/win32" "$(cygpath -m "$ROOT")/src/adhoc_crypto.c" /LD "/Fe:$WORK/lib.dll" "/Fo:$WORK/adhoc_crypto.obj" /link /OPT:REF /OPT:ICF "$WORK/b/ssl.lib" "$WORK/b/crypto.lib" ws2_32.lib advapi32.lib user32.lib
    cp "$WORK/lib.dll" "$OUT/libadhoc-crypto-$VERSION.dll"
    ;;
  darwin)
    cmake -S "$SRC" -B "$WORK/b" "${GEN[@]}" -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
    cmake --build "$WORK/b" --target ssl crypto
    clang -O2 -dynamiclib -fvisibility=hidden -mmacosx-version-min=11.0 -I"$SRC/include" -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin" "$ROOT/src/adhoc_crypto.c" "$WORK/b/libssl.a" "$WORK/b/libcrypto.a" -lc++ -Wl,-dead_strip -o "$OUT/libadhoc-crypto-$VERSION.dylib"
    strip -x "$OUT/libadhoc-crypto-$VERSION.dylib"
    ;;
  linux | linux-musl | freebsd)
    cmake -S "$SRC" -B "$WORK/b" "${GEN[@]}" -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    cmake --build "$WORK/b" --target ssl crypto
    JNI_OS=${OS%-musl}
    # BoringSSL is C++: its runtime goes inside the library, which then needs only libc, libm and libpthread.
    gcc -c -O2 -fPIC -fvisibility=hidden -I"$SRC/include" -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/$JNI_OS" "$ROOT/src/adhoc_crypto.c" -o "$WORK/adhoc_crypto.o"
    g++ -shared "$WORK/adhoc_crypto.o" "$WORK/b/libssl.a" "$WORK/b/libcrypto.a" -static-libstdc++ -static-libgcc -Wl,--exclude-libs,ALL -Wl,-z,noexecstack -Wl,-z,relro,-z,now -Wl,--gc-sections -lpthread -o "$OUT/libadhoc-crypto-$VERSION.so"
    strip "$OUT/libadhoc-crypto-$VERSION.so"
    ;;
  *) echo "unknown os $OS" >&2; exit 2 ;;
esac
ls -la "$OUT"
