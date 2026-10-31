# adhoc-crypto

The native library of the [AdHoc protocol](https://github.com/AdHoc-Protocol/AdHoc-protocol) runtimes: ciphers, Noise, TLS 1.3 on BoringSSL, and
the chain of TLS, WebSocket frames and Noise in one call per buffer. The runtimes reach it through JNI (Java) and the plain C exports of
`src/adhoc_crypto.h` (the others).

You do not need this repository to use AdHoc: the library comes with the generated code. It exists to build the binaries.

## What a push to `main` does

`.github/workflows/release.yml` builds and tests every platform BoringSSL builds for and replaces the latest release:

| File | What it is |
|:--|:--|
| `adhoc-crypto.jar` | for Java, in the layout of zstd-jni: `<os>/<arch>/libadhoc-crypto-<version>.<ext>` |
| `adhoc-crypto.zip` | for the other languages: `<rid>/libadhoc-crypto-<version>.<ext>` |
| `SHA256SUMS.txt` | the sums of the two |

| System | Processors |
|:--|:--|
| Windows | x64, x86, arm64 |
| Linux | x64, arm64, x86, arm, riscv64 |
| Linux with musl | x64, arm64 |
| macOS | x64, arm64 |
| FreeBSD | x64 |

BoringSSL is its latest main at every build. `VERSION` is the version in the name of the file, and the runtimes look for that name.

## Build by hand

```bash
bash scripts/build.sh linux amd64 "$(cat VERSION)"
bash scripts/jar.sh "$(cat VERSION)"
bash scripts/pack.sh
bash test/test.sh "out/adhoc-crypto-$(cat VERSION).jar"
```

`JAVA_HOME` gives `jni.h` and `jar`; `BORINGSSL` may name a checkout. Linux needs cmake, ninja and g++; Windows clang-cl, cmake, ninja, nasm and vcvars.
`java/` holds the classes that load the library, the same as in the Java runtime: the tests need them.

## License

Apache License 2.0, see `LICENSE` and `NOTICE`.
