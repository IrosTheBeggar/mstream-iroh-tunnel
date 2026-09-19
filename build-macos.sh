#!/usr/bin/env bash
# Build iroh_tunnel.xcframework for macOS (arm64) and stage it under
# dist/macos/ — or under $IROH_TUNNEL_DEST, so a consumer can point this
# straight at its own tree (the mStream mobile app's macos/ side of its
# iroh_tunnel_native SwiftPM package). Same model as build-ios.sh: consumers
# that ship the binary commit it on their side or take a release asset.
#
# Prereqs: host Rust toolchain + Xcode command line tools. Apple-silicon only.
set -euo pipefail
cd "$(dirname "$0")"

export MACOSX_DEPLOYMENT_TARGET=11.0
unset SDKROOT

FW=iroh_tunnel
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
DEST="${IROH_TUNNEL_DEST:-dist/macos}"
STAGE="target/macos-stage"

cargo build --release --lib --target aarch64-apple-darwin

# Versioned macOS framework (macOS rejects iOS's shallow layout).
fwdir="$STAGE/macos-arm64/$FW.framework"
rm -rf "$fwdir"
mkdir -p "$fwdir/Versions/A/Resources"
cp "target/aarch64-apple-darwin/release/lib$FW.dylib" "$fwdir/Versions/A/$FW"
install_name_tool -id "@rpath/$FW.framework/Versions/A/$FW" "$fwdir/Versions/A/$FW"
cat > "$fwdir/Versions/A/Resources/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>$FW</string>
  <key>CFBundleIdentifier</key><string>mstream.music.iroh-tunnel</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>$FW</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleSupportedPlatforms</key><array><string>MacOSX</string></array>
  <key>LSMinimumSystemVersion</key><string>$MACOSX_DEPLOYMENT_TARGET</string>
</dict>
</plist>
PLIST
ln -sfn A "$fwdir/Versions/Current"
ln -sfn Versions/Current/$FW "$fwdir/$FW"
ln -sfn Versions/Current/Resources "$fwdir/Resources"
codesign --force --sign - "$fwdir"

mkdir -p "$DEST"
rm -rf "$DEST/$FW.xcframework"
xcodebuild -create-xcframework \
  -framework "$fwdir" \
  -output "$DEST/$FW.xcframework"

# The C ABI v2 export set (src/c_api.rs) — keep in step
# with build-ios.sh.
n=$(xcrun dyld_info -exports "$DEST/$FW.xcframework/macos-arm64/$FW.framework/$FW" | grep -c ' _mstream_iroh_')
[ "$n" -eq 15 ] || { echo "ERROR: exports $n/15 mstream_iroh_ symbols"; exit 1; }
echo "staged: $DEST/$FW.xcframework"
