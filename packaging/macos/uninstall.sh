#!/bin/sh
# Remove the Votal agent (run as root). Keeps nothing behind.
launchctl bootout system/com.votal.agent 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.votal.agent.plist
rm -rf /Library/Votal "/Library/Application Support/Votal" /Library/Logs/Votal
pkgutil --forget com.votal.agent 2>/dev/null || true
