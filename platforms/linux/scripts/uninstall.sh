#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/votal/nexus"
STATE_DIR="/var/lib/votal/nexus"
SERVICE_PATH="/etc/systemd/system/nexus-agent.service"
PURGE_DATA=0

[[ ${EUID} -eq 0 ]] || { echo "uninstall.sh must run as root" >&2; exit 1; }

if [[ "${1:-}" == "--purge-data" ]]; then
  PURGE_DATA=1
  shift
fi
[[ $# -eq 0 ]] || { echo "Usage: uninstall.sh [--purge-data]" >&2; exit 2; }

systemctl disable --now nexus-agent.service >/dev/null 2>&1 || true
rm -f "$SERVICE_PATH"
rm -rf "$INSTALL_DIR"
systemctl daemon-reload

if [[ "$PURGE_DATA" -eq 1 ]]; then
  rm -rf "$STATE_DIR"
  echo "Removed Nexus state and policy data."
else
  echo "Preserved Nexus state at $STATE_DIR."
fi
echo "Uninstalled Nexus Agent."
