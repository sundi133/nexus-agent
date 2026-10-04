#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CORE_DIR="${REPO_ROOT}/core"
OUTPUT_DIR="${REPO_ROOT}/platforms/macos/Package/Generated"

command -v cargo >/dev/null 2>&1 || {
  echo "cargo is required to build nexus-agent-core" >&2
  exit 1
}
command -v rustup >/dev/null 2>&1 || {
  echo "rustup is required to install Apple Rust targets" >&2
  exit 1
}

rustup target add aarch64-apple-darwin x86_64-apple-darwin

cargo build --manifest-path "${CORE_DIR}/Cargo.toml" --release --target aarch64-apple-darwin
cargo build --manifest-path "${CORE_DIR}/Cargo.toml" --release --target x86_64-apple-darwin

mkdir -p "${OUTPUT_DIR}"
xcrun lipo -create \
  "${CORE_DIR}/target/aarch64-apple-darwin/release/libnexus_agent_core.a" \
  "${CORE_DIR}/target/x86_64-apple-darwin/release/libnexus_agent_core.a" \
  -output "${OUTPUT_DIR}/libnexus_agent_core.a"

echo "Built ${OUTPUT_DIR}/libnexus_agent_core.a"
