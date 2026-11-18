#!/bin/bash
#
# AppDump-decrypt - unsigned IPA builder
#
#   ./build.sh              -> build/AppDump.ipa   (Release)
#   ./build.sh --debug      -> build/AppDump.ipa   (Debug, shows the Debug Only section)
#
# Requirements: macOS + Xcode 16 or newer (the project uses synchronized folder
# groups, so older Xcode will refuse to open it).
#
set -euo pipefail

APP_NAME=AppDump
IPA_NAME=AppDump
ROOT="$(cd "$(dirname "$0")" && pwd)"
CONFIG=Release

if [[ "${1:-}" == "--debug" ]]; then
    CONFIG=Debug
fi

cd "$ROOT"
rm -rf build
mkdir -p build

echo "[*] building $APP_NAME ($CONFIG) for iphoneos..."

xcodebuild \
    -project "$APP_NAME.xcodeproj" \
    -scheme "$APP_NAME" \
    -configuration "$CONFIG" \
    -sdk iphoneos \
    -derivedDataPath "$ROOT/build/DerivedData" \
    -destination 'generic/platform=iOS' \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGN_ENTITLEMENTS="" \
    build

APP_PATH="$ROOT/build/DerivedData/Build/Products/$CONFIG-iphoneos/$APP_NAME.app"

if [ ! -d "$APP_PATH" ]; then
    echo "ERROR: build product not found at $APP_PATH" >&2
    exit 1
fi

echo "[*] stripping any leftover signature..."
rm -rf "$APP_PATH/_CodeSignature" "$APP_PATH/embedded.mobileprovision"

echo "[*] packaging payload..."
rm -rf "$ROOT/build/Payload"
mkdir -p "$ROOT/build/Payload"
cp -R "$APP_PATH" "$ROOT/build/Payload/"
(cd "$ROOT/build" && zip -qry "$IPA_NAME.ipa" Payload)
rm -rf "$ROOT/build/Payload"

echo
echo "[*] done -> build/$IPA_NAME.ipa"
echo "[*] install: sign it on-device (ESign / Feather / Sideloadly) or with your own cert."
