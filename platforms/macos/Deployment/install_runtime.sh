#!/bin/zsh
set -euo pipefail

RUNTIME_DIR="/Library/Application Support/Votal/NexusRuntime"
STATE_DIR="/Library/Application Support/Votal/Nexus"
PLIST_PATH="/Library/LaunchDaemons/ai.votal.nexus.runtime.plist"
RUNTIME_USER="_votalnexus"
RUNTIME_GROUP="_votalnexus"

usage() {
  echo "Usage: install_runtime.sh <nexus-agent-runtime> <runtime.json> <policy-public-key.b64>" >&2
  exit 2
}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $# -eq 3 ]] || usage

RUNTIME_BINARY="$1"
RUNTIME_CONFIG="$2"
PUBLIC_KEY="$3"

[[ -f "$RUNTIME_BINARY" ]] || { echo "runtime binary missing: $RUNTIME_BINARY" >&2; exit 1; }
[[ -f "$RUNTIME_CONFIG" ]] || { echo "runtime config missing: $RUNTIME_CONFIG" >&2; exit 1; }
[[ -f "$PUBLIC_KEY" ]] || { echo "policy public key missing: $PUBLIC_KEY" >&2; exit 1; }

if ! dscl . -read "/Groups/$RUNTIME_GROUP" >/dev/null 2>&1; then
  gid="$(dscl . -list /Groups PrimaryGroupID | awk '$2 >= 200 && $2 < 500 {print $2}' | sort -n | awk 'BEGIN{g=200}{if($1==g){g++}else if($1>g){print g; exit}} END{if(NR==0) print 200}')"
  dscl . -create "/Groups/$RUNTIME_GROUP"
  dscl . -create "/Groups/$RUNTIME_GROUP" PrimaryGroupID "$gid"
fi

if ! dscl . -read "/Users/$RUNTIME_USER" >/dev/null 2>&1; then
  uid="$(dscl . -list /Users UniqueID | awk '$2 >= 200 && $2 < 500 {print $2}' | sort -n | awk 'BEGIN{u=200}{if($1==u){u++}else if($1>u){print u; exit}} END{if(NR==0) print 200}')"
  gid="$(dscl . -read "/Groups/$RUNTIME_GROUP" PrimaryGroupID | awk '{print $2}')"
  dscl . -create "/Users/$RUNTIME_USER"
  dscl . -create "/Users/$RUNTIME_USER" UserShell /usr/bin/false
  dscl . -create "/Users/$RUNTIME_USER" RealName "Votal Nexus Runtime"
  dscl . -create "/Users/$RUNTIME_USER" UniqueID "$uid"
  dscl . -create "/Users/$RUNTIME_USER" PrimaryGroupID "$gid"
  dscl . -create "/Users/$RUNTIME_USER" NFSHomeDirectory /var/empty
fi

mkdir -p "$RUNTIME_DIR" "$STATE_DIR"
install -m 0755 -o root -g wheel "$RUNTIME_BINARY" "$RUNTIME_DIR/nexus-agent-runtime"
install -m 0644 -o root -g wheel "$RUNTIME_CONFIG" "$RUNTIME_DIR/runtime.json"
install -m 0644 -o root -g wheel "$PUBLIC_KEY" "$RUNTIME_DIR/policy-public-key.b64"

chown "$RUNTIME_USER:$RUNTIME_GROUP" "$STATE_DIR"
chmod 0770 "$STATE_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
install -m 0644 -o root -g wheel "$SCRIPT_DIR/ai.votal.nexus.runtime.plist" "$PLIST_PATH"

launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable system/ai.votal.nexus.runtime

echo "Installed Votal Nexus managed runtime."
echo "Runtime: $RUNTIME_DIR/nexus-agent-runtime"
echo "Config:  $RUNTIME_DIR/runtime.json"
echo "State:   $STATE_DIR"
echo "Provision the bearer-token file referenced by runtime.json so $RUNTIME_USER can read it."
