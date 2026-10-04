#!/bin/bash
set -euo pipefail

RUNTIME_USER="_votalnexus"
RUNTIME_GROUP="_votalnexus"
INSTALL_DIR="/Library/Application Support/Votal/NexusRuntime"
STATE_DIR="/Library/Application Support/Votal/Nexus"
PLIST_PATH="/Library/LaunchDaemons/ai.votal.nexus.runtime.plist"

usage() {
  echo "Usage: install-runtime.sh <nexus-agent-runtime> <runtime.json> <policy-public-key.b64>" >&2
  exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "install-runtime.sh must run as root" >&2; exit 1; }
[[ $# -eq 3 ]] || usage

SOURCE_RUNTIME="$1"
SOURCE_CONFIG="$2"
SOURCE_PUBLIC_KEY="$3"
[[ -f "$SOURCE_RUNTIME" ]] || { echo "runtime binary not found: $SOURCE_RUNTIME" >&2; exit 1; }
[[ -f "$SOURCE_CONFIG" ]] || { echo "runtime config not found: $SOURCE_CONFIG" >&2; exit 1; }
[[ -f "$SOURCE_PUBLIC_KEY" ]] || { echo "policy public key not found: $SOURCE_PUBLIC_KEY" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_SOURCE="${SCRIPT_DIR}/ai.votal.nexus.runtime.plist"

next_available_id() {
  local kind="$1"
  local attribute="$2"
  local id
  for id in $(seq 450 499); do
    if ! dscl . -list "/$kind" "$attribute" 2>/dev/null | awk '{print $2}' | grep -qx "$id"; then
      echo "$id"
      return 0
    fi
  done
  echo "no free service identity ID in 450-499" >&2
  return 1
}

if ! dscl . -read "/Groups/$RUNTIME_GROUP" >/dev/null 2>&1; then
  GROUP_ID="$(next_available_id Groups PrimaryGroupID)"
  dscl . -create "/Groups/$RUNTIME_GROUP"
  dscl . -create "/Groups/$RUNTIME_GROUP" PrimaryGroupID "$GROUP_ID"
  dscl . -create "/Groups/$RUNTIME_GROUP" RealName "Votal Nexus Runtime"
else
  GROUP_ID="$(dscl . -read "/Groups/$RUNTIME_GROUP" PrimaryGroupID | awk '{print $2}')"
fi

if ! dscl . -read "/Users/$RUNTIME_USER" >/dev/null 2>&1; then
  USER_ID="$(next_available_id Users UniqueID)"
  dscl . -create "/Users/$RUNTIME_USER"
  dscl . -create "/Users/$RUNTIME_USER" UniqueID "$USER_ID"
  dscl . -create "/Users/$RUNTIME_USER" PrimaryGroupID "$GROUP_ID"
  dscl . -create "/Users/$RUNTIME_USER" UserShell /usr/bin/false
  dscl . -create "/Users/$RUNTIME_USER" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$RUNTIME_USER" RealName "Votal Nexus Runtime"
fi

launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true

install -d -m 0755 -o root -g wheel "$INSTALL_DIR"
install -d -m 0770 -o root -g "$RUNTIME_GROUP" "$STATE_DIR"
install -m 0755 -o root -g wheel "$SOURCE_RUNTIME" "$INSTALL_DIR/nexus-agent-runtime"
install -m 0644 -o root -g wheel "$SOURCE_CONFIG" "$INSTALL_DIR/runtime.json"
install -m 0644 -o root -g wheel "$SOURCE_PUBLIC_KEY" "$INSTALL_DIR/policy-public-key.b64"
install -m 0644 -o root -g wheel "$PLIST_SOURCE" "$PLIST_PATH"

# Rewrite only local filesystem paths. Control-plane URLs and bearer-token path
# remain deployment-owned values from the supplied config.
python3 - "$INSTALL_DIR/runtime.json" "$STATE_DIR" "$INSTALL_DIR/policy-public-key.b64" <<'PY'
import json, pathlib, sys
config_path = pathlib.Path(sys.argv[1])
state = pathlib.Path(sys.argv[2])
public_key = pathlib.Path(sys.argv[3])
data = json.loads(config_path.read_text())
data["spool_dir"] = str(state / "spool")
data["policy_signed_path"] = str(state / "policy.signed.json")
data["policy_watermark_path"] = str(state / "policy.version")
data["policy_public_key_file"] = str(public_key)
data["event_source_path"] = str(state / "events.jsonl")
data["event_offset_path"] = str(state / "events.offset")
data["health_source_path"] = str(state / "health.json")
config_path.write_text(json.dumps(data, indent=2) + "\n")
PY
chmod 0644 "$INSTALL_DIR/runtime.json"

plutil -lint "$PLIST_PATH" >/dev/null
launchctl bootstrap system "$PLIST_PATH"
launchctl enable system/ai.votal.nexus.runtime
launchctl kickstart -k system/ai.votal.nexus.runtime

echo "Installed macOS Nexus managed runtime."
echo "Runtime: $INSTALL_DIR/nexus-agent-runtime"
echo "Config:  $INSTALL_DIR/runtime.json"
echo "State:   $STATE_DIR"
echo "Provision the bearer-token file referenced by runtime.json with read access for $RUNTIME_USER."
