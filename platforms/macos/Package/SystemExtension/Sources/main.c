#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <os/log.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "NexusTrustRoot.h"
#include "nexus_core.h"

#define POLICY_PATH "/Library/Application Support/Votal/Nexus/policy.signed.json"
#define MAX_POLICY_BYTES (1024 * 1024)

static os_log_t g_log;
static NexusPolicyHandle *g_policy = NULL;
static atomic_bool g_kill_switch = false;

static bool trust_root_configured(void) {
    for (size_t i = 0; i < sizeof(NEXUS_POLICY_PUBLIC_KEY); ++i) {
        if (NEXUS_POLICY_PUBLIC_KEY[i] != 0) {
            return true;
        }
    }
    return false;
}

static unsigned char *read_file(const char *path, size_t *length) {
    *length = 0;

    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    long size = ftell(file);
    if (size <= 0 || size > MAX_POLICY_BYTES) {
        fclose(file);
        return NULL;
    }

    rewind(file);
    unsigned char *buffer = malloc((size_t)size);
    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }

    size_t read_count = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    if (read_count != (size_t)size) {
        free(buffer);
        return NULL;
    }

    *length = read_count;
    return buffer;
}

static bool load_verified_policy(void) {
    if (!trust_root_configured()) {
        os_log_error(g_log,
                     "policy trust root is not configured; extension remains allow-only");
        return false;
    }

    size_t envelope_length = 0;
    unsigned char *envelope = read_file(POLICY_PATH, &envelope_length);
    if (envelope == NULL) {
        os_log_error(g_log,
                     "signed policy unavailable at %{public}s; extension remains allow-only",
                     POLICY_PATH);
        return false;
    }

    NexusPolicyHandle *verified = nexus_policy_from_signed_json(
        envelope,
        envelope_length,
        NEXUS_POLICY_PUBLIC_KEY,
        sizeof(NEXUS_POLICY_PUBLIC_KEY));
    free(envelope);

    if (verified == NULL) {
        os_log_error(g_log,
                     "signed policy verification failed; extension remains allow-only");
        return false;
    }

    g_policy = verified;
    os_log(g_log,
           "verified signed endpoint policy version %{public}llu",
           (unsigned long long)nexus_policy_version(g_policy));
    return true;
}

static void set_kill_switch(int signo) {
    (void)signo;
    atomic_store_explicit(&g_kill_switch, true, memory_order_relaxed);
}

static void clear_kill_switch(int signo) {
    (void)signo;
    atomic_store_explicit(&g_kill_switch, false, memory_order_relaxed);
}

static void handle_auth_exec(es_client_t *client, const es_message_t *message) {
    if (message == NULL ||
        atomic_load_explicit(&g_kill_switch, memory_order_relaxed) ||
        g_policy == NULL ||
        message->event.exec.target == NULL ||
        message->event.exec.target->executable == NULL) {
        if (message != NULL) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        }
        return;
    }

    es_string_token_t path = message->event.exec.target->executable->path;
    NexusDecision decision = nexus_policy_evaluate_exec(
        g_policy,
        (const uint8_t *)path.data,
        path.length);

    es_auth_result_t result =
        decision == NEXUS_DECISION_DENY ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW;

    es_respond_result_t response =
        es_respond_auth_result(client, message, result, false);

    if (response != ES_RESPOND_RESULT_SUCCESS) {
        os_log_error(g_log,
                     "failed responding to AUTH_EXEC: %{public}d",
                     response);
    }
}

int main(void) {
    g_log = os_log_create("ai.votal.nexus.agent.endpoint", "endpoint-security");
    signal(SIGUSR1, set_kill_switch);
    signal(SIGUSR2, clear_kill_switch);

    /*
     * Policy loading and signature verification happen before ES subscription.
     * Verification failure leaves g_policy NULL, which makes every callback
     * fail open.
     */
    (void)load_verified_policy();

    es_client_t *client = NULL;
    es_new_client_result_t result =
        es_new_client(&client, ^(es_client_t *callback_client, const es_message_t *message) {
            handle_auth_exec(callback_client, message);
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        os_log_error(g_log, "es_new_client failed: %{public}d", result);
        if (g_policy != NULL) {
            nexus_policy_free(g_policy);
            g_policy = NULL;
        }
        return EXIT_FAILURE;
    }

    const es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    if (es_subscribe(client, events, 1) != ES_RETURN_SUCCESS) {
        os_log_error(g_log, "es_subscribe failed");
        es_delete_client(client);
        if (g_policy != NULL) {
            nexus_policy_free(g_policy);
            g_policy = NULL;
        }
        return EXIT_FAILURE;
    }

    os_log(g_log,
           "Nexus Endpoint Security extension started; policy_loaded=%{public}s",
           g_policy != NULL ? "true" : "false");
    dispatch_main();
    return EXIT_SUCCESS;
}
