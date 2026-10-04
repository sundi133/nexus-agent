# Endpoint control-plane contract

This document defines the client-side contract only. Endpoint URLs are deployment configuration, not constants in the agent.

## Policy

**Request**

- HTTPS GET to the configured policy URL.
- `Authorization: Bearer <device credential>`.
- Optional `If-None-Match` using the ETag from the last successfully activated policy.

**Response**

- `304 Not Modified`; or
- `2xx` with a JSON `SignedPolicyEnvelope`.

The agent activates a response only after Ed25519 verification, policy structural validation, and anti-rollback checks. A bad response leaves the last-known-good policy active.

## Health

HTTPS POST of the shared `AgentHealth` object. Capability state must describe what is actually active: `active`, `shadow`, `fallback`, or `unavailable`.

Health is not part of synchronous enforcement. Failure to report health must not hang process/file/network authorization.

## Events

HTTPS POST with content type `application/x-ndjson`. A successful HTTP status acknowledges the uploaded disk-spool segment. Timeouts and non-success statuses leave the segment for retry.

## Authentication and enrollment

The runtime supports two mutually exclusive credential sources:

1. legacy protected bearer-token file; or
2. a protected server-issued device credential bundle.

New deployments should use the device credential bundle:

```json
{
  "device_id": "device-01JABC...",
  "bearer_token": "<opaque device credential>",
  "expires_at": "2026-11-01T00:00:00Z"
}
```

The runtime re-reads this file for every policy, health, and event request, so an atomic file replacement rotates the credential without restarting the service. When a bundle is used, requests include:

- `Authorization: Bearer <device credential>`
- `X-Nexus-Device-Id: <device_id>`

The bearer credential and policy-signing trust root remain separate.

### One-time enrollment

`nexus-enroll` performs the bootstrap exchange:

```sh
nexus-enroll \
  --url https://control.example/v1/endpoint/enroll \
  --bootstrap-token-file /secure/bootstrap.token \
  --output /var/lib/votal/nexus/device.credential.json
```

The client POST body contains only:

```json
{
  "platform": "linux",
  "architecture": "x86_64",
  "agent_version": "0.1.0"
}
```

The bootstrap token is sent only as the HTTPS bearer credential and is never included in JSON. The server returns the device credential bundle shown above. Nexus validates it and atomically replaces the output file.

The bootstrap token should be one-time or short-lived and removed after successful enrollment.

### Rotation

Rotation is a file-level atomic operation: issue a newer device credential bundle and atomically replace the configured `device_credential_file`. Because transport reads the credential on every request, no endpoint-agent restart is required.

A future server-side renewal protocol may automate issuance before `expires_at`; the local runtime already supports hot replacement.

## Trust boundaries

The policy-signing key and transport authentication credential are separate. Compromise of a device credential must not allow an attacker to create a valid endpoint policy because policy still requires the pinned Ed25519 signing trust root. Enrollment bootstrap tokens must never be accepted as policy-signing material.
