#!/bin/bash
set -euo pipefail

RUNTIME_USER="_votalnexus"
RUNTIME_GROUP="_votalnexus"
INSTALL_DIR="/Library/Application Support/Votal/NexusRuntime"
STATE_DIR="/Library/Application Support/Votal/Nexus"
PLIST_PATH="/Library/LaunchDaemons/ai.votal.nexus.runtime.plist"
PURGE=0

[[ ${EUID} -eq 0 ]] || { echo "uninstall-runtime.sh must run as root" >&2; exit 1; }

if [[ "${1:-}" == "--purge-data" ]]; then
  PURGE=1
  shift
fi
[[ $# -eq 0 ]] || { echo "Usage: uninstall-runtime.sh [--purge-data]" >&2; exit 2; }

launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
rm -f "$PLIST_PATH"
rm -rf "$INSTALL_DIR"

if [[ "$PURGE" -eq 1 ]]; then
  rm -rf "$STATE_DIR"
  dscl . -delete "/Users/$RUNTIME_USER" >/dev/null 2>&1 || true
  dscl . -delete "/Groups/$RUNTIME_GROUP" >/dev/null 2>&1 || true
  echo "Removed runtime state and service identity."
else
  echo "Preserved shared Nexus state at $STATE_DIR."
  echo "Preserved service identity $RUNTIME_USER."
fi

echo "Uninstalled macOS Nexus managed runtime."
