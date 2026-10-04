# Linux nftables controlled network enforcement

`nft_control.sh` provides a narrow development harness for real outbound network blocking.

It creates a dedicated `inet votal_nexus` table and an output hook that drops one exact IPv4 destination. Removal deletes the entire Nexus-owned test table, making rollback deterministic.

## Isolated test

```sh
sudo platforms/linux/scripts/nft_control.sh install 203.0.113.10
sudo platforms/linux/scripts/nft_control.sh remove
```

Use a destination you control. Do not begin with DNS, SSH bastions, package repositories, identity providers, VPN infrastructure, endpoint management, security tooling, or other critical destinations.

This is not yet wired to signed policy. Production application should translate verified policy into an atomic nftables batch and expose the active rules in agent health.
