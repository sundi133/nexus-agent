# Nexus managed runtime

The runtime crate is the network/control-plane layer for Nexus endpoint agents. It is intentionally separate from the synchronous enforcement core.

## Responsibilities

- Fetch signed policy over HTTPS.
- Verify policy locally before activation.
- Reject policy rollback.
- Upload machine-readable health.
- Upload newline-delimited endpoint events.
- Buffer events in a bounded on-disk spool while offline.
- Re-read the bearer token file on every request so credentials can rotate without restarting the endpoint agent.

The runtime must never be invoked directly from Endpoint Security, fanotify permission, WFP classification, or other synchronous authorization callbacks.

## Configuration

No Votal endpoint is hard-coded. The deployment supplies explicit HTTPS URLs:

```json
{
  "control_plane": {
    "policy_url": "https://control.example/v1/endpoint/policy",
    "health_url": "https://control.example/v1/endpoint/health",
    "events_url": "https://control.example/v1/endpoint/events",
    "bearer_token_file": "/var/lib/votal/nexus/device.token",
    "connect_timeout_ms": 5000,
    "request_timeout_ms": 30000
  },
  "spool_dir": "/var/lib/votal/nexus/spool",
  "policy_signed_path": "/var/lib/votal/nexus/policy.signed.json",
  "policy_watermark_path": "/var/lib/votal/nexus/policy.version",
  "spool_max_bytes": 67108864,
  "segment_max_bytes": 4194304
}
```

Windows deployments use equivalent paths under `C:\ProgramData\Votal\Nexus\`.

## Policy response

The policy endpoint returns the existing `SignedPolicyEnvelope` JSON document. ETags are supported: the runtime sends `If-None-Match` after a successful activation and accepts HTTP 304.

An HTTP 200 response is **not** enough to activate policy. The Ed25519 signature, structure, and version watermark must all pass locally.

## Telemetry behavior

Events are written to local JSONL segments first. Upload acknowledgement deletes a segment only after the events endpoint returns a successful HTTP status. Failed uploads leave the segment queued.

The spool is bounded. If it exceeds its configured maximum, the oldest segments are removed and the local dropped-segment counter increases. Production health/check-in should surface that counter.

## Credential handling

The bearer token is read from a file for each request and is never placed in the repository or runtime JSON. Protect that file with platform-native ACLs. Long term, device enrollment should provision a device-bound credential into Keychain/DPAPI/TPM-backed storage rather than leaving a reusable bootstrap secret on disk.


## Sidecar executable

The runtime crate now also builds `nexus-agent-runtime`. It is intended to run outside the privileged enforcement callback path.

It:

- tails the platform collector's local `events.jsonl`;
- appends each complete event to the bounded durable spool before advancing the persisted read offset;
- ignores incomplete trailing JSONL records until the writer finishes them;
- reads the platform `health.json` snapshot;
- fetches and verifies signed policy into the shared policy path;
- uploads health and spooled telemetry over HTTPS.

Start it with:

```sh
nexus-agent-runtime /etc/votal/nexus/runtime.json
```

The policy public-key file contains only the pinned 32-byte Ed25519 public key encoded as base64. Protect the runtime configuration, trust-root file, bearer-token file, and state directory with platform ACLs.

Telemetry ingestion is intentionally at-least-once. A crash between durable spooling and offset checkpointing may replay an event, but it should not lose one. The control plane should deduplicate by `event_id` where appropriate.
