#!/usr/bin/env bash
set -euo pipefail

TABLE_FAMILY="inet"
TABLE_NAME="votal_nexus"
CHAIN_NAME="output"

usage() {
  cat >&2 <<'EOF'
Usage:
  nft_control.sh install <remote-ipv4>
  nft_control.sh remove

Installs one exact outbound IPv4 destination block in an isolated Nexus nftables table.
Run only on an isolated test endpoint until policy integration and rollback testing are complete.
EOF
  exit 2
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "nft_control.sh must run as root" >&2
    exit 1
  fi
}

validate_ipv4() {
  local ip="$1"
  python3 - "$ip" <<'PY'
import ipaddress, sys
try:
    value = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if value.version != 4:
    raise SystemExit(1)
PY
}

remove_table() {
  if nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    nft delete table "$TABLE_FAMILY" "$TABLE_NAME"
  fi
}

install_rule() {
  local remote_ip="$1"

  if ! validate_ipv4 "$remote_ip"; then
    echo "invalid IPv4 address: $remote_ip" >&2
    exit 2
  fi

  # Replace the complete isolated table atomically enough for this single-rule
  # development harness. Production policy application should use an nft batch.
  remove_table

  nft add table "$TABLE_FAMILY" "$TABLE_NAME"
  nft "add chain $TABLE_FAMILY $TABLE_NAME $CHAIN_NAME { type filter hook output priority -5; policy accept; }"
  nft add rule "$TABLE_FAMILY" "$TABLE_NAME" "$CHAIN_NAME"     ip daddr "$remote_ip" counter drop comment '"nexus-test-block"'

  echo "Installed Nexus nftables block for destination $remote_ip"
}

main() {
  [[ $# -ge 1 ]] || usage
  require_root
  command -v nft >/dev/null 2>&1 || {
    echo "nft command not found" >&2
    exit 1
  }

  case "$1" in
    install)
      [[ $# -eq 2 ]] || usage
      install_rule "$2"
      ;;
    remove)
      [[ $# -eq 1 ]] || usage
      remove_table
      echo "Removed Nexus nftables test table"
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
