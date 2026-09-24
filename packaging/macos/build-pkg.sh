#!/bin/sh
# Build VotalAgent.pkg from a universal (arm64+amd64) binary.
#
#   packaging/macos/build-pkg.sh <version>
#
# Signing/notarization (required for distribution outside MDM):
#   DEVELOPER_ID_APP="Developer ID Application: Votal Inc (TEAMID)"
#   DEVELOPER_ID_INSTALLER="Developer ID Installer: Votal Inc (TEAMID)"
#   NOTARY_PROFILE=votal-notary   # xcrun notarytool store-credentials
set -eu
VERSION="${1:?version required}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIST="$ROOT/dist"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

lipo -create -output "$WORK/votal-agent" \
  "$DIST/votal-agent_darwin_arm64" "$DIST/votal-agent_darwin_amd64"

if [ -n "${DEVELOPER_ID_APP:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID_APP" "$WORK/votal-agent"
fi

mkdir -p "$WORK/root/Library/Votal" "$WORK/root/Library/LaunchDaemons"
cp "$WORK/votal-agent" "$WORK/root/Library/Votal/votal-agent"
chmod 755 "$WORK/root/Library/Votal/votal-agent"
cp "$ROOT/packaging/macos/com.votal.agent.plist" "$WORK/root/Library/LaunchDaemons/"
chmod +x "$ROOT/packaging/macos/scripts/"*

pkgbuild --root "$WORK/root" --scripts "$ROOT/packaging/macos/scripts" \
  --identifier com.votal.agent --version "$VERSION" --install-location / \
  "$WORK/component.pkg"

OUT="$DIST/VotalAgent-$VERSION.pkg"
if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
  productbuild --package "$WORK/component.pkg" --sign "$DEVELOPER_ID_INSTALLER" "$OUT"
else
  productbuild --package "$WORK/component.pkg" "$OUT"
fi

if [ -n "${NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$OUT"
fi
echo "built $OUT"
