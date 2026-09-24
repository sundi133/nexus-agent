#!/bin/sh
set -e
install -d -m 0700 /etc/votal /var/lib/votal
# Automated installs may set VOTAL_SERVER_URL / VOTAL_ENROLLMENT_TOKEN.
if [ -n "${VOTAL_SERVER_URL:-}" ]; then
  /usr/bin/votal-agent configure -server-url "$VOTAL_SERVER_URL" \
    ${VOTAL_ENROLLMENT_TOKEN:+-enrollment-token "$VOTAL_ENROLLMENT_TOKEN"}
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable votal-agent.service
  # Only start once configured; otherwise the admin runs `votal-agent configure`.
  if [ -f /etc/votal/config.json ]; then
    systemctl restart votal-agent.service
  fi
fi
