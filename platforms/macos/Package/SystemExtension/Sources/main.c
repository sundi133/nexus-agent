#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <os/log.h>
#include <pthread.h>
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
static pthread_rwlock_t g_policy_lock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_bool g_kill_switch = false;
static atomic_bool g_reload_requested = false;

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

static NexusPolicyHandle *read_verified_policy(void) {
    if (!trust_root_configured()) {
        os_log_error(g_log,
                     "policy trust root is not configured; extension remains allow-only");
        return NULL;
    }

    size_t envelope_length = 0;
    unsigned char *envelope = read_file(POLICY_PATH, &envelope_length);
    if (envelope == NULL) {
        os_log_error(g_log,
                     "signed policy unavailable at %{public}s; extension remains allow-only",
                     POLICY_PATH);
        return NULL;
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
        return NULL;
    }

    return verified;
}

static bool reload_verified_policy(void) {
    NexusPolicyHandle *verified = read_verified_policy();
    if (verified == NULL) {
        os_log_error(g_log,
                     "policy reload rejected; retaining last-known-good policy");
        return false;
    }

    pthread_rwlock_wrlock(&g_policy_lock);
    NexusPolicyHandle *previous = g_policy;
    g_policy = verified;
    uint64_t version = nexus_policy_version(g_policy);
    pthread_rwlock_unlock(&g_policy_lock);

    if (previous != NULL) {
        nexus_policy_free(previous);
    }

    os_log(g_log,
           "activated verified endpoint policy version %{public}llu",
           (unsigned long long)version);
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

static void request_policy_reload(int signo) {
    (void)signo;
    atomic_store_explicit(&g_reload_requested, true, memory_order_relaxed);
}

static void handle_auth_exec(es_client_t *client, const es_message_t *message) {
    if (message == NULL ||
        atomic_load_explicit(&g_kill_switch, memory_order_relaxed) ||
        message->event.exec.target == NULL ||
        message->event.exec.target->executable == NULL) {
        if (message != NULL) {
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        }
        return;
    }

    es_string_token_t path = message->event.exec.target->executable->path;

    pthread_rwlock_rdlock(&g_policy_lock);
    NexusPolicyHandle *policy = g_policy;
    NexusDecision decision = policy == NULL
        ? NEXUS_DECISION_ALLOW
        : nexus_policy_evaluate_exec(
              policy,
              (const uint8_t *)path.data,
              path.length);
    pthread_rwlock_unlock(&g_policy_lock);

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
    signal(SIGHUP, request_policy_reload);

    /*
     * Policy loading and signature verification happen before ES subscription.
     * Verification failure leaves g_policy NULL, which makes every callback
     * fail open.
     */
    (void)reload_verified_policy();

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

    dispatch_queue_t maintenance_queue =
        dispatch_queue_create("ai.votal.nexus.agent.endpoint.maintenance",
                              DISPATCH_QUEUE_SERIAL);
    dispatch_source_t reload_timer =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, maintenance_queue);
    dispatch_source_set_timer(reload_timer,
                              dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
                              NSEC_PER_SEC,
                              100 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(reload_timer, ^{
        if (atomic_exchange_explicit(&g_reload_requested,
                                     false,
                                     memory_order_relaxed)) {
            (void)reload_verified_policy();
        }
    });
    dispatch_resume(reload_timer);

    pthread_rwlock_rdlock(&g_policy_lock);
    bool policy_loaded = g_policy != NULL;
    pthread_rwlock_unlock(&g_policy_lock);

    os_log(g_log,
           "Nexus Endpoint Security extension started; policy_loaded=%{public}s; SIGHUP reloads policy",
           policy_loaded ? "true" : "false");
    dispatch_main();
    return EXIT_SUCCESS;
}
