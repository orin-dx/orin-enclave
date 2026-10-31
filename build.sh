#!/bin/bash
# Build "Orin Enclave.app" with the hardened runtime.
#   ./build.sh [output-dir]                          ad hoc signature (default output: ./build)
#   SIGN_IDENTITY="Developer ID Application: ..." ./build.sh
#                                                    sign with a certificate, with a secure timestamp
#   TEST_BUILD=1 ./build.sh                          build/orin-enclave-test only: state under
#                                                    $OE_TEST_STATE_DIR; never install this one
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
cd "$(dirname "$0")"

OUT=${1:-build}
IDENTITY=${SIGN_IDENTITY:--}
BUNDLE_ID=dev.orin-dx.enclave
mkdir -p "$OUT"

sign() {
  local args=(--force --options runtime --sign "$IDENTITY" --identifier "$1")
  [[ $IDENTITY != - ]] && args+=(--timestamp)
  codesign "${args[@]}" "$2"
  codesign --verify --strict --verbose=1 "$2"
}

if [[ ${TEST_BUILD:-0} == 1 ]]; then
  swiftc -O -swift-version 5 -D OE_TEST_BUILD Sources/main.swift -o "$OUT/orin-enclave-test"
  sign "$BUNDLE_ID.test" "$OUT/orin-enclave-test"
  echo "$OUT/orin-enclave-test"
  exit 0
fi

APP="$OUT/Orin Enclave.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

swiftc -O -swift-version 5 Sources/main.swift -o "$APP/Contents/MacOS/orin-enclave"
cp Resources/Info.plist "$APP/Contents/Info.plist"

if [[ -f Resources/AppIcon.icns ]]; then
  cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
else
  # Fall back to rendering the icon from the 1024 px master.
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  mkdir "$work/AppIcon.iconset"
  for size in 16 32 128 256 512; do
    sips -z $size $size assets/icon-1024.png --out "$work/AppIcon.iconset/icon_${size}x${size}.png" >/dev/null
    sips -z $((size * 2)) $((size * 2)) assets/icon-1024.png \
      --out "$work/AppIcon.iconset/icon_${size}x${size}@2x.png" >/dev/null
  done
  iconutil -c icns "$work/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
fi

sign "$BUNDLE_ID" "$APP"
echo "$APP"
