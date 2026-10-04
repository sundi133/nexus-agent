#ifndef NEXUS_CORE_H
#define NEXUS_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NexusPolicyHandle NexusPolicyHandle;

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

#ifdef __cplusplus
}
#endif

#endif
