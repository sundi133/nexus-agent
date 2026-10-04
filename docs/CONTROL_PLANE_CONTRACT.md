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

## Authentication

The current transport accepts a device bearer token from a protected local file and re-reads it for rotation. This is a bootstrap mechanism, not the final enrollment design.

Recommended production progression:

1. one-time enrollment token;
2. device keypair generated locally;
3. control plane issues a short-lived/device-bound credential;
4. private key stored using platform-native protection;
5. routine credential rotation without reinstalling the agent.

## Trust boundaries

The policy-signing key and transport authentication credential are separate. Compromise of the bearer credential must not allow an attacker to create a valid endpoint policy because policy still requires the pinned Ed25519 signing trust root.
