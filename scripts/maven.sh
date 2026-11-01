#!/usr/bin/env bash
# Lays out out/adhoc-crypto-<version>.jar as a bundle of Maven Central: out/adhoc-crypto-<version>.<number>-bundle.zip, jar, pom, sources and
# javadoc with their signatures and sums, in the layout of a Maven repository.
#
#   maven.sh <version> <number>         the version names the file of the library, the number counts the builds of it
#
# GPG_PASSPHRASE opens the key of gpg that signs. The javadoc has no classes to show, the jar has only the native library: its README says so.
set -euo pipefail
VERSION=$1
NUMBER=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$ROOT/out}
FULL=$VERSION.$NUMBER
WORK=$OUT/maven
DIR=$WORK/org/unirail/adhoc-crypto/$FULL
NAME=adhoc-crypto-$FULL
rm -rf "$WORK" "$OUT/$NAME-bundle.zip"
mkdir -p "$DIR" "$WORK/javadoc"
cp "$OUT/adhoc-crypto-$VERSION.jar" "$DIR/$NAME.jar"
"$JAVA_HOME/bin/jar" --create --no-manifest --file "$DIR/$NAME-sources.jar" -C "$ROOT/src" .
printf 'The native library of the AdHoc runtime. The jar has no classes: see %s\n' https://github.com/AdHoc-Protocol/adhoc-crypto > "$WORK/javadoc/README"
"$JAVA_HOME/bin/jar" --create --no-manifest --file "$DIR/$NAME-javadoc.jar" -C "$WORK/javadoc" .
rm -rf "$WORK/javadoc"
cat > "$DIR/$NAME.pom" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.unirail</groupId>
  <artifactId>adhoc-crypto</artifactId>
  <version>$FULL</version>
  <packaging>jar</packaging>
  <name>adhoc-crypto</name>
  <description>The native library of the AdHoc runtime: BoringSSL and the chain of TLS, WebSocket frames and Noise, for every platform BoringSSL builds for.</description>
  <url>https://github.com/AdHoc-Protocol/adhoc-crypto</url>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
  <developers>
    <developer>
      <name>Chikirev Sirguy</name>
      <organization>Unirail Group</organization>
      <url>https://github.com/AdHoc-Protocol</url>
    </developer>
  </developers>
  <scm>
    <connection>scm:git:https://github.com/AdHoc-Protocol/adhoc-crypto.git</connection>
    <developerConnection>scm:git:https://github.com/AdHoc-Protocol/adhoc-crypto.git</developerConnection>
    <url>https://github.com/AdHoc-Protocol/adhoc-crypto</url>
  </scm>
</project>
EOF
cd "$DIR"
for file in "$NAME.jar" "$NAME-sources.jar" "$NAME-javadoc.jar" "$NAME.pom"; do
  printf '%s' "$GPG_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --armor --detach-sign "$file"
  md5sum "$file" | cut -d' ' -f1 > "$file.md5"
  sha1sum "$file" | cut -d' ' -f1 > "$file.sha1"
done
"$JAVA_HOME/bin/jar" --create --no-manifest --file "$OUT/$NAME-bundle.zip" -C "$WORK" org
rm -rf "$WORK"
ls -la "$OUT/$NAME-bundle.zip"
