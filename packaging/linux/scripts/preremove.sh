#!/bin/sh
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop votal-agent.service || true
  systemctl disable votal-agent.service || true
fi
