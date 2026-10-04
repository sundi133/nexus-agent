# Signed policy lab workflow

Nexus Agent policy bundles use Ed25519 signatures. The private signing key must stay outside endpoint binaries and outside this repository.

## Create a lab signing key

Generate 32 random bytes with an appropriate secret-management workflow. For a disposable local lab on macOS/Linux, one option is:

```sh
export NEXUS_POLICY_SIGNING_KEY_B64="$(openssl rand -base64 32)"
```

Do not use a shell environment variable as the long-term production key store. Production signing should use a restricted control-plane signing service or managed key system.

## Sign a policy

From the repository root:

```sh
cargo run --manifest-path core/Cargo.toml --bin nexus-policy-sign -- \
  lab-key-1 core/examples/policy.json /tmp/policy.signed.json
```

The utility prints the corresponding public key. The endpoint trust root contains **only that 32-byte public key**.

## Validate the safety path

1. Keep policies in audit/shadow mode first.
2. Install the signed envelope at the platform-specific policy path.
3. Configure the matching public trust root in the test build.
4. Confirm the endpoint reports the expected policy version.
5. Tamper with one byte of the signed envelope and confirm the replacement is rejected.
6. Only after rollback and kill-switch tests should a narrow test rule be placed in enforcement mode.

Never distribute the private key with an endpoint installer, MDM profile, configuration file, source repository, or CI artifact.
