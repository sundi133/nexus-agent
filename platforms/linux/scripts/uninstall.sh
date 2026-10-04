#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/votal/nexus"
STATE_DIR="/var/lib/votal/nexus"
CONFIG_DIR="/etc/votal/nexus"
AGENT_SERVICE_PATH="/etc/systemd/system/nexus-agent.service"
RUNTIME_SERVICE_PATH="/etc/systemd/system/nexus-runtime.service"
PURGE_DATA=0

[[ ${EUID} -eq 0 ]] || { echo "uninstall.sh must run as root" >&2; exit 1; }

if [[ "${1:-}" == "--purge-data" ]]; then
  PURGE_DATA=1
  shift
fi
[[ $# -eq 0 ]] || { echo "Usage: uninstall.sh [--purge-data]" >&2; exit 2; }

systemctl disable --now nexus-runtime.service >/dev/null 2>&1 || true
systemctl disable --now nexus-agent.service >/dev/null 2>&1 || true
rm -f "$RUNTIME_SERVICE_PATH" "$AGENT_SERVICE_PATH"
rm -rf "$INSTALL_DIR"
systemctl daemon-reload

if [[ "$PURGE_DATA" -eq 1 ]]; then
  rm -rf "$STATE_DIR" "$CONFIG_DIR"
  if id nexus-runtime >/dev/null 2>&1; then
    userdel nexus-runtime >/dev/null 2>&1 || true
  fi
  if getent group votal-nexus >/dev/null 2>&1; then
    groupdel votal-nexus >/dev/null 2>&1 || true
  fi
  echo "Removed Nexus state, runtime configuration, and service identity."
else
  echo "Preserved Nexus state at $STATE_DIR."
  if [[ -d "$CONFIG_DIR" ]]; then
    echo "Preserved Nexus runtime configuration at $CONFIG_DIR."
  fi
fi

echo "Uninstalled Nexus Agent and managed runtime services."
