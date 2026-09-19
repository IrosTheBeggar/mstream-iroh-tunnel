#!/usr/bin/env bash
# Build libiroh_tunnel.so for Android (arm64-v8a + x86_64, API 26) and stage it
# under dist/android/<abi>/ — or under $IROH_TUNNEL_DEST/<abi>/, so a consumer
# can point this straight at its own tree (the mStream mobile app:
#   IROH_TUNNEL_DEST=../mstream_music/android/app/src/main/jniLibs ./build-android.sh).
#
# Consumers that ship the binary commit it on their side (the mobile app's
# release CI has no Rust/NDK toolchain, so it packages the committed .so) or
# take it from a tagged release's assets. Their rule: after a bump, re-stage
# and re-commit — a stale binary is the one failure packaging checks cannot see.
#
# Prereqs (one-time):
#   rustup target add aarch64-linux-android x86_64-linux-android
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=.../Android/Sdk/ndk/28.2.13676358
#
# Usage:  ./build-android.sh
set -euo pipefail
cd "$(dirname "$0")"

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your NDK, e.g. .../Android/Sdk/ndk/28.2.13676358}"

DEST="${IROH_TUNNEL_DEST:-dist/android}"

# --platform 26 matches the mobile app's minSdk. The flag is --platform (NOT -p, which
# cargo passes through to cargo as --package).
cargo ndk -t arm64-v8a -t x86_64 --platform 26 build --release --lib

# Stage ONLY our cdylib. cargo-ndk's -o would also copy spurious dependency
# dylibs (libiroh-<hash>.so / libiroh_relay-<hash>.so) that libiroh_tunnel.so
# already statically links — dead weight in the APK.
for pair in "arm64-v8a:aarch64-linux-android" "x86_64:x86_64-linux-android"; do
  abi="${pair%%:*}"; triple="${pair##*:}"
  mkdir -p "$DEST/$abi"
  cp "target/$triple/release/libiroh_tunnel.so" "$DEST/$abi/libiroh_tunnel.so"
done

echo "staged:"
ls -lh "$DEST"/*/libiroh_tunnel.so
