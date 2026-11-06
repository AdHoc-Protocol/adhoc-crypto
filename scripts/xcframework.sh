#!/usr/bin/env bash
# Puts out/natives/ios/arm64 and out/natives/iossimulator/{arm64,x86_64} into out/adhoc-crypto.xcframework.zip: adhoc_crypto.framework for
# a device and for the simulator, what an app of Xcode embeds. Each file also goes out alone as out/adhoc-crypto-<rid>.dylib
# ( ios-arm64, iossimulator-arm64, iossimulator-x64 ): what the build hook of Dart hands the SDK, which makes the framework itself.
#
#   xcframework.sh <version>
set -euo pipefail
VERSION=$1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
N=$ROOT/out/natives
F=$ROOT/out/frameworks
FILE=libadhoc-crypto-$VERSION.dylib
rm -rf "$F" "$ROOT/out/adhoc-crypto.xcframework" "$ROOT/out/adhoc-crypto.xcframework.zip"

framework() { # <folder> <library> <platform of the bundle>
  local d=$F/$1/adhoc_crypto.framework
  mkdir -p "$d"
  cp "$2" "$d/adhoc_crypto"
  cat > "$d/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>en</string>
	<key>CFBundleExecutable</key><string>adhoc_crypto</string>
	<key>CFBundleIdentifier</key><string>org.unirail.adhoc-crypto</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>adhoc_crypto</string>
	<key>CFBundlePackageType</key><string>FMWK</string>
	<key>CFBundleShortVersionString</key><string>$VERSION</string>
	<key>CFBundleVersion</key><string>$VERSION</string>
	<key>CFBundleSupportedPlatforms</key><array><string>$3</string></array>
	<key>MinimumOSVersion</key><string>13.0</string>
</dict>
</plist>
EOF
}

framework ios "$N/ios/arm64/$FILE" iPhoneOS
mkdir -p "$F/sim"
lipo -create "$N/iossimulator/arm64/$FILE" "$N/iossimulator/x86_64/$FILE" -output "$F/sim/$FILE"
framework iossimulator "$F/sim/$FILE" iPhoneSimulator
xcodebuild -create-xcframework -framework "$F/ios/adhoc_crypto.framework" -framework "$F/iossimulator/adhoc_crypto.framework" -output "$ROOT/out/adhoc-crypto.xcframework"
( cd "$ROOT/out" && ditto -c -k --sequesterRsrc --keepParent adhoc-crypto.xcframework adhoc-crypto.xcframework.zip )

cp "$N/ios/arm64/$FILE" "$ROOT/out/adhoc-crypto-ios-arm64.dylib"
cp "$N/iossimulator/arm64/$FILE" "$ROOT/out/adhoc-crypto-iossimulator-arm64.dylib"
cp "$N/iossimulator/x86_64/$FILE" "$ROOT/out/adhoc-crypto-iossimulator-x64.dylib"
ls -la "$ROOT/out/adhoc-crypto.xcframework.zip" "$ROOT"/out/adhoc-crypto-ios*.dylib
