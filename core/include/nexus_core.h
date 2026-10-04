#ifndef NEXUS_CORE_H
#define NEXUS_CORE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NexusPolicyHandle NexusPolicyHandle;
typedef struct NexusRansomwareTrackerHandle NexusRansomwareTrackerHandle;

typedef struct NexusRansomwareAssessment {
    uint8_t score;
    uint8_t severity;
} NexusRansomwareAssessment;

typedef struct NexusRansomwareResponse {
    bool matched;
    bool would_enforce;
    bool enforce;
    uint8_t action;
} NexusRansomwareResponse;

typedef enum NexusDecision {
    NEXUS_DECISION_ALLOW = 0,
    NEXUS_DECISION_DENY = 1,
    NEXUS_DECISION_ALERT = 2,
    NEXUS_DECISION_ERROR = 255
} NexusDecision;

/*
 * Parses and verifies a JSON SignedPolicyEnvelope using a raw 32-byte Ed25519
 * public key. Returns NULL on parse/signature/policy failure.
 */
NexusPolicyHandle *nexus_policy_from_signed_json(
    const uint8_t *envelope_ptr,
    size_t envelope_len,
    const uint8_t *public_key_ptr,
    size_t public_key_len);

void nexus_policy_free(NexusPolicyHandle *handle);
uint64_t nexus_policy_version(const NexusPolicyHandle *handle);

NexusDecision nexus_policy_evaluate_exec(
    const NexusPolicyHandle *handle,
    const uint8_t *path_ptr,
    size_t path_len);

NexusRansomwareTrackerHandle *nexus_ransomware_tracker_new(
    uint64_t window_ms,
    size_t max_processes);

void nexus_ransomware_tracker_free(NexusRansomwareTrackerHandle *handle);

/* severity: 0=low, 1=medium, 2=high, 3=critical, 255=error */
NexusRansomwareAssessment nexus_ransomware_observe_path(
    NexusRansomwareTrackerHandle *handle,
    uint32_t pid,
    uint64_t now_ms,
    const uint8_t *path_ptr,
    size_t path_len,
    bool renamed);

bool nexus_ransomware_mark_suspicious_process(
    NexusRansomwareTrackerHandle *handle,
    uint32_t pid,
    uint64_t now_ms);

/* action: 0=alert, 1=terminate_process, 2=network_isolate,
 * 3=terminate_and_network_isolate, 255=none/error */
NexusRansomwareResponse nexus_ransomware_plan_response(
    const NexusPolicyHandle *policy_handle,
    NexusRansomwareTrackerHandle *tracker_handle,
    uint32_t pid,
    uint8_t score,
    uint8_t severity);

#ifdef __cplusplus
}
#endif

#endif
