#ifndef NEXUS_TRUST_ROOT_H
#define NEXUS_TRUST_ROOT_H

#include <stdint.h>

/*
 * Replace this development placeholder with the 32-byte Ed25519 public key
 * used to sign production policy bundles. The extension refuses to enforce
 * policy while this trust root is all zeros.
 *
 * Do not embed the private signing key anywhere in the endpoint agent.
 */
static const uint8_t NEXUS_POLICY_PUBLIC_KEY[32] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

#endif
