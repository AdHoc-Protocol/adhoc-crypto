#!/usr/bin/env bash
# Builds out/natives/<os>/<arch>/libadhoc-crypto-<version>.<ext> for the platform it runs on: BoringSSL, statically, and the
# JNI code around it. In gen/ BoringSSL has its assembly ready, so neither Perl nor Go is needed; on Windows x86-64 NASM is.
#
#   build.sh <os> <arch> <version>      os: win, linux, linux-musl, darwin, freebsd, android, ios, iossimulator; arch: amd64, aarch64, x86_64, x86, i386, arm, riscv64; on android its ABI; on ios arm64, on iossimulator arm64 or x86_64
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
  ios | iossimulator)
    # A dynamic library named as the binary of adhoc_crypto.framework: an app of iOS carries a library only in a framework ( xcframework.sh ).
    # One architecture a build: BoringSSL takes no two at once.
    SDK=iphoneos TARGET=$ARCH-apple-ios13.0
    [ "$OS" = iossimulator ] && SDK=iphonesimulator TARGET=$ARCH-apple-ios13.0-simulator
    cmake -S "$SRC" -B "$WORK/b" "${GEN[@]}" -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=$SDK -DCMAKE_OSX_ARCHITECTURES=$ARCH -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0
    cmake --build "$WORK/b" --target ssl crypto
    clang -O2 -dynamiclib -fvisibility=hidden -target "$TARGET" -isysroot "$(xcrun --sdk $SDK --show-sdk-path)" -I"$SRC/include" -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin" "$ROOT/src/adhoc_crypto.c" "$WORK/b/libssl.a" "$WORK/b/libcrypto.a" -lc++ -Wl,-dead_strip -install_name @rpath/adhoc_crypto.framework/adhoc_crypto -o "$OUT/libadhoc-crypto-$VERSION.dylib"
    strip -x "$OUT/libadhoc-crypto-$VERSION.dylib"
    ;;
  linux | linux-musl | freebsd)
    # -Wno-stringop-overflow: a false alarm of GCC inside BoringSSL on riscv64, and BoringSSL builds with -Werror. The clang of FreeBSD does not know the flag.
    QUIET=
    [ "$OS" = freebsd ] || QUIET=-Wno-stringop-overflow
    cmake -S "$SRC" -B "$WORK/b" "${GEN[@]}" -DCMAKE_POSITION_INDEPENDENT_CODE=ON "-DCMAKE_C_FLAGS=$QUIET" "-DCMAKE_CXX_FLAGS=$QUIET"
    cmake --build "$WORK/b" --target ssl crypto
    JNI_OS=${OS%-musl}
    # BoringSSL is C++: its runtime goes inside the library, which then needs only libc, libm and libpthread. An image with no static one: the system's at run time.
    STATIC=(-static-libstdc++ -static-libgcc)
    [ -f "$(g++ -print-file-name=libstdc++.a)" ] || STATIC=(-static-libgcc)
    gcc -c -O2 -fPIC -fvisibility=hidden -I"$SRC/include" -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/$JNI_OS" "$ROOT/src/adhoc_crypto.c" -o "$WORK/adhoc_crypto.o"
    g++ -shared "$WORK/adhoc_crypto.o" "$WORK/b/libssl.a" "$WORK/b/libcrypto.a" "${STATIC[@]}" -Wl,--exclude-libs,ALL -Wl,-z,noexecstack -Wl,-z,relro,-z,now -Wl,--gc-sections -lpthread -o "$OUT/libadhoc-crypto-$VERSION.so"
    strip "$OUT/libadhoc-crypto-$VERSION.so"
    ;;
  android)
    # arch is the ABI of Android. ANDROID_NDK_ROOT is the NDK. 16 KB pages: what Android asks of a library from version 15.
    API=24
    case $ARCH in
      arm64-v8a) T=aarch64-linux-android ;;
      armeabi-v7a) T=armv7a-linux-androideabi ;;
      x86_64) T=x86_64-linux-android ;;
      x86) T=i686-linux-android ;;
      *) echo "unknown ABI $ARCH" >&2; exit 2 ;;
    esac
    TOOLS=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
    cmake -S "$SRC" -B "$WORK/b" "${GEN[@]}" "-DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" "-DANDROID_ABI=$ARCH" "-DANDROID_PLATFORM=android-$API"
    cmake --build "$WORK/b" --target ssl crypto
    "$TOOLS/$T$API-clang" -c -O2 -fPIC -fvisibility=hidden -I"$SRC/include" "$ROOT/src/adhoc_crypto.c" -o "$WORK/adhoc_crypto.o"
    "$TOOLS/$T$API-clang++" -shared "$WORK/adhoc_crypto.o" "$WORK/b/libssl.a" "$WORK/b/libcrypto.a" -static-libstdc++ -Wl,--exclude-libs,ALL -Wl,-z,noexecstack -Wl,-z,relro,-z,now -Wl,-z,max-page-size=16384 -Wl,--gc-sections -o "$OUT/libadhoc-crypto-$VERSION.so"
    "$TOOLS/llvm-strip" "$OUT/libadhoc-crypto-$VERSION.so"
    ;;
  *) echo "unknown os $OS" >&2; exit 2 ;;
esac
ls -la "$OUT"
