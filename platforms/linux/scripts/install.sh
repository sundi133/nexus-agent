#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/votal/nexus"
STATE_DIR="/var/lib/votal/nexus"
SERVICE_PATH="/etc/systemd/system/nexus-agent.service"
NO_START=0

usage() {
  echo "Usage: install.sh [--no-start] <path-to-nexus-agent-linux>" >&2
  exit 2
}

[[ ${EUID} -eq 0 ]] || { echo "install.sh must run as root" >&2; exit 1; }

if [[ "${1:-}" == "--no-start" ]]; then
  NO_START=1
  shift
fi

[[ $# -eq 1 ]] || usage
SOURCE_BINARY="$1"
[[ -f "$SOURCE_BINARY" ]] || { echo "binary not found: $SOURCE_BINARY" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_SOURCE="${SCRIPT_DIR}/../nexus-agent.service"

install -d -m 0755 -o root -g root "$INSTALL_DIR"
install -d -m 0700 -o root -g root "$STATE_DIR"
install -m 0755 -o root -g root "$SOURCE_BINARY" "$INSTALL_DIR/nexus-agent-linux"
install -m 0644 -o root -g root "$SERVICE_SOURCE" "$SERVICE_PATH"

systemctl daemon-reload
systemctl enable nexus-agent.service
if [[ "$NO_START" -eq 0 ]]; then systemctl restart nexus-agent.service; fi

echo "Installed Nexus Agent."
echo "Binary: $INSTALL_DIR/nexus-agent-linux"
echo "State:  $STATE_DIR"
echo "No signed policy or control-plane credential was created by this installer."
