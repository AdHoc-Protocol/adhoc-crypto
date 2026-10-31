#!/usr/bin/env bash
# Runs TestAll against a jar: test.sh <jar> [online]. No network unless asked. With OPENSSL naming a binary, an OpenSSL server too.
# Bench instead of TestAll: MAIN=Bench test.sh <jar>
set -euo pipefail
export MSYS_NO_PATHCONV=1
JAR=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
shift
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$HERE/../out/test}
mkdir -p "$WORK"
cd "$WORK"
SEP=:
case $(uname -s) in MINGW* | MSYS* | CYGWIN*) SEP=';'; JAR=$(cygpath -w "$JAR") ;; esac
KT="$JAVA_HOME/bin/keytool"

if [ ! -f server.p12 ]; then
  "$KT" -genkeypair -alias server -keyalg EC -groupname secp256r1 -dname CN=localhost -ext SAN=dns:localhost -validity 30 -storetype PKCS12 -keystore server.p12 -storepass benchpass 2>/dev/null
  "$KT" -exportcert -alias server -rfc -file cert.pem -keystore server.p12 -storepass benchpass 2>/dev/null
fi
if [ ! -f expired.p12 ]; then
  "$KT" -genkeypair -alias ca -keyalg EC -groupname secp256r1 -dname CN=test-ca -ext bc:c -startdate -30d -validity 365 -storetype PKCS12 -keystore expired.p12 -storepass benchpass 2>/dev/null
  "$KT" -genkeypair -alias leaf -keyalg EC -groupname secp256r1 -dname CN=localhost -storetype PKCS12 -keystore expired.p12 -storepass benchpass 2>/dev/null
  "$KT" -certreq -alias leaf -keystore expired.p12 -storepass benchpass -file leaf.csr
  "$KT" -gencert -alias ca -infile leaf.csr -outfile leaf.crt -ext SAN=dns:localhost -startdate -10d -validity 2 -keystore expired.p12 -storepass benchpass -rfc
  "$KT" -importcert -alias leaf -file leaf.crt -keystore expired.p12 -storepass benchpass -noprompt 2>/dev/null
fi
if [ -n "${OPENSSL:-}" ] && [ ! -f key.pem ]; then
  "$OPENSSL" pkcs12 -in server.p12 -passin pass:benchpass -nocerts -nodes -out key.pem 2>/dev/null
fi
SRC=$HERE
case $(uname -s) in MINGW* | MSYS* | CYGWIN*) SRC=$(cygpath -w "$HERE") ;; esac
LIB=$HERE/../java/org/unirail/crypto
case $(uname -s) in MINGW* | MSYS* | CYGWIN*) LIB=$(cygpath -w "$LIB") ;; esac
"$JAVA_HOME/bin/javac" -encoding UTF-8 -d classes "$LIB/Crypto.java" "$LIB/Native.java" "$LIB/Tls13.java" "$SRC/TestAll.java" "$SRC/Bench.java"
exec "$JAVA_HOME/bin/java" ${JAVA_OPTS:-} -cp "classes$SEP$JAR" "${MAIN:-TestAll}" "$@"
