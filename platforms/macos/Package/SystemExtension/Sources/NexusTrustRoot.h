#ifndef NEXUS_TRUST_ROOT_H
#define NEXUS_TRUST_ROOT_H

#include <stdint.h>

/*
 * Optional compile-time fallback trust root. Production deployment normally
 * provisions the base64 public key as a root-owned file through the installer.
 * This fallback may remain all-zero; if both sources are unavailable or invalid,
 * the extension remains fail-open.
 *
 * Never embed the private signing key anywhere in the endpoint agent.
 */
static const uint8_t NEXUS_POLICY_PUBLIC_KEY[32] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

#endif
