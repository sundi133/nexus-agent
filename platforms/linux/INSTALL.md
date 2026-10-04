# Linux installation scaffold

Build the Linux agent, then install it as root:

~~~sh
cargo build --release --manifest-path platforms/linux/Cargo.toml
sudo platforms/linux/scripts/install.sh platforms/linux/target/release/nexus-agent-linux
~~~

The installer creates a root-owned `/var/lib/votal/nexus` state directory with mode `0700`, installs the binary under `/opt/votal/nexus`, and enables the systemd unit. It does not generate a policy signing key, signed policy, or control-plane token.

Uninstall preserves state by default:

~~~sh
sudo platforms/linux/scripts/uninstall.sh
~~~

Use `--purge-data` only when policy, event spool, health data, and local credentials should also be destroyed.

Production packages should use native DEB/RPM packaging and signing for the supported distribution matrix rather than these shell scripts as the final installer.
