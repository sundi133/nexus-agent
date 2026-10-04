#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/votal/nexus"
STATE_DIR="/var/lib/votal/nexus"
CONFIG_DIR="/etc/votal/nexus"
AGENT_SERVICE_PATH="/etc/systemd/system/nexus-agent.service"
RUNTIME_SERVICE_PATH="/etc/systemd/system/nexus-runtime.service"
NO_START=0

usage() {
  cat >&2 <<'EOF'
Usage:
  install.sh [--no-start] <path-to-nexus-agent-linux>
  install.sh [--no-start] <path-to-nexus-agent-linux> <path-to-nexus-agent-runtime> <runtime-config.json> <policy-public-key.b64>

The four-argument form also installs the non-root managed runtime sidecar.
It does not create a device bearer token.
EOF
  exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "install.sh must run as root" >&2; exit 1; }

if [[ "${1:-}" == "--no-start" ]]; then
  NO_START=1
  shift
fi

[[ $# -eq 1 || $# -eq 4 ]] || usage

SOURCE_AGENT="$1"
[[ -f "$SOURCE_AGENT" ]] || { echo "agent binary not found: $SOURCE_AGENT" >&2; exit 1; }

INSTALL_RUNTIME=0
if [[ $# -eq 4 ]]; then
  INSTALL_RUNTIME=1
  SOURCE_RUNTIME="$2"
  SOURCE_CONFIG="$3"
  SOURCE_PUBLIC_KEY="$4"

  [[ -f "$SOURCE_RUNTIME" ]] || { echo "runtime binary not found: $SOURCE_RUNTIME" >&2; exit 1; }
  [[ -f "$SOURCE_CONFIG" ]] || { echo "runtime config not found: $SOURCE_CONFIG" >&2; exit 1; }
  [[ -f "$SOURCE_PUBLIC_KEY" ]] || { echo "policy public key not found: $SOURCE_PUBLIC_KEY" >&2; exit 1; }
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SERVICE_SOURCE="${SCRIPT_DIR}/../nexus-agent.service"
RUNTIME_SERVICE_SOURCE="${SCRIPT_DIR}/../nexus-runtime.service"

install -d -m 0755 -o root -g root "$INSTALL_DIR"
install -m 0755 -o root -g root "$SOURCE_AGENT" "$INSTALL_DIR/nexus-agent-linux"

if [[ "$INSTALL_RUNTIME" -eq 1 ]]; then
  getent group votal-nexus >/dev/null 2>&1 || groupadd --system votal-nexus
  id nexus-runtime >/dev/null 2>&1 ||     useradd --system --gid votal-nexus --no-create-home --shell /usr/sbin/nologin nexus-runtime

  install -d -m 0770 -o root -g votal-nexus "$STATE_DIR"
  install -d -m 0750 -o root -g votal-nexus "$CONFIG_DIR"
  install -m 0755 -o root -g root "$SOURCE_RUNTIME" "$INSTALL_DIR/nexus-agent-runtime"
  install -m 0640 -o root -g votal-nexus "$SOURCE_CONFIG" "$CONFIG_DIR/runtime.json"
  install -m 0640 -o root -g votal-nexus "$SOURCE_PUBLIC_KEY" "$CONFIG_DIR/policy-public-key.b64"
  install -m 0644 -o root -g root "$RUNTIME_SERVICE_SOURCE" "$RUNTIME_SERVICE_PATH"
else
  install -d -m 0700 -o root -g root "$STATE_DIR"
fi

install -m 0644 -o root -g root "$AGENT_SERVICE_SOURCE" "$AGENT_SERVICE_PATH"

systemctl daemon-reload
systemctl enable nexus-agent.service
if [[ "$INSTALL_RUNTIME" -eq 1 ]]; then
  systemctl enable nexus-runtime.service
fi

if [[ "$NO_START" -eq 0 ]]; then
  systemctl restart nexus-agent.service
  if [[ "$INSTALL_RUNTIME" -eq 1 ]]; then
    systemctl restart nexus-runtime.service
  fi
fi

echo "Installed Nexus Agent."
echo "Agent binary: $INSTALL_DIR/nexus-agent-linux"
echo "State:        $STATE_DIR"
if [[ "$INSTALL_RUNTIME" -eq 1 ]]; then
  echo "Runtime:      $INSTALL_DIR/nexus-agent-runtime"
  echo "Config:       $CONFIG_DIR/runtime.json"
  echo "Trust root:   $CONFIG_DIR/policy-public-key.b64"
  echo "Provision the bearer-token file referenced by runtime.json before expecting control-plane connectivity."
else
  echo "Managed runtime sidecar was not installed."
fi
echo "No signed policy or control-plane credential was created by this installer."
