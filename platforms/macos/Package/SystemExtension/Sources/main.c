#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <os/log.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "NexusTrustRoot.h"
#include "nexus_core.h"

#define POLICY_PATH "/Library/Application Support/Votal/Nexus/policy.signed.json"
#define POLICY_VERSION_PATH "/Library/Application Support/Votal/Nexus/policy.version"
#define HEALTH_PATH "/Library/Application Support/Votal/Nexus/health.json"
#define CONTAINMENT_DISABLE_PATH "/Library/Application Support/Votal/Nexus/disable-containment"
#define MAX_POLICY_BYTES (1024 * 1024)

static os_log_t g_log;
static NexusPolicyHandle *g_policy = NULL;
static pthread_rwlock_t g_policy_lock = PTHREAD_RWLOCK_INITIALIZER;
static atomic_bool g_kill_switch = false;
static atomic_bool g_reload_requested = false;
static NexusRansomwareTrackerHandle *g_ransomware_tracker = NULL;

static void ensure_state_directory(void) {
    (void)mkdir("/Library/Application Support/Votal", 0755);
    (void)mkdir("/Library/Application Support/Votal/Nexus", 0755);
}

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

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static uint64_t read_policy_watermark(void) {
    FILE *file = fopen(POLICY_VERSION_PATH, "r");
    if (file == NULL) {
        return 0;
    }

    unsigned long long value = 0;
    int parsed = fscanf(file, "%llu", &value);
    fclose(file);
    return parsed == 1 ? (uint64_t)value : 0;
}

static bool write_policy_watermark(uint64_t version) {
    FILE *file = fopen(POLICY_VERSION_PATH, "w");
    if (file == NULL) {
        return false;
    }
    int written = fprintf(file, "%llu\n", (unsigned long long)version);
    bool ok = written > 0 && fclose(file) == 0;
    return ok;
}

static void write_health_file(void) {
    NexusRansomwareResponseConfig response_config = {
        .configured = false,
        .mode = 255,
        .action = 255,
        .min_score = 0,
        .require_suspicious_process_context = false
    };

    pthread_rwlock_rdlock(&g_policy_lock);
    uint64_t policy_version =
        g_policy == NULL ? 0 : nexus_policy_version(g_policy);
    if (g_policy != NULL) {
        response_config = nexus_policy_ransomware_response_config(g_policy);
    }
    pthread_rwlock_unlock(&g_policy_lock);

    bool kill_switch =
        atomic_load_explicit(&g_kill_switch, memory_order_relaxed);
    bool local_disable = access(CONTAINMENT_DISABLE_PATH, F_OK) == 0;

    const char *response_state = "unavailable";
    char response_detail[256];
    snprintf(response_detail,
             sizeof(response_detail),
             "no ransomware response configured");

    if (response_config.configured) {
        if (response_config.mode == 1) {
            response_state = "shadow";
            snprintf(response_detail,
                     sizeof(response_detail),
                     "shadow action=%u min_score=%u require_context=%s",
                     response_config.action,
                     response_config.min_score,
                     response_config.require_suspicious_process_context
                         ? "true" : "false");
        } else if (response_config.mode == 2) {
            if (kill_switch || local_disable) {
                response_state = "shadow";
                snprintf(response_detail,
                         sizeof(response_detail),
                         "enforce policy present but containment is locally disabled");
            } else if (response_config.action == 1) {
                response_state = "active";
                snprintf(response_detail,
                         sizeof(response_detail),
                         "terminate-process containment active min_score=%u require_context=%s",
                         response_config.min_score,
                         response_config.require_suspicious_process_context
                             ? "true" : "false");
            } else {
                response_state = "shadow";
                snprintf(response_detail,
                         sizeof(response_detail),
                         "configured action=%u is not executable by macOS containment",
                         response_config.action);
            }
        } else {
            snprintf(response_detail,
                     sizeof(response_detail),
                     "ransomware response disabled by signed policy");
        }
    }

    FILE *file = fopen(HEALTH_PATH, "w");
    if (file == NULL) {
        os_log_error(g_log, "cannot write health file at %{public}s", HEALTH_PATH);
        return;
    }

    fprintf(
        file,
        "{\n"
        "  \"schema_version\": 1,\n"
        "  \"platform\": \"macos\",\n"
        "  \"policy_version\": ");
    if (policy_version == 0) {
        fputs("null", file);
    } else {
        fprintf(file, "%llu", (unsigned long long)policy_version);
    }
    fprintf(
        file,
        ",\n"
        "  \"kill_switch_engaged\": %s,\n"
        "  \"capabilities\": [\n"
        "    {\"name\":\"endpoint_security\",\"state\":\"active\",\"detail\":\"Endpoint Security system extension subscribed\"},\n"
        "    {\"name\":\"process_enforcement\",\"state\":\"%s\",\"detail\":\"AUTH_EXEC local signed-policy enforcement\"},\n"
        "    {\"name\":\"ransomware_detection\",\"state\":\"shadow\",\"detail\":\"unique-path file behavior correlation\"},\n"
        "    {\"name\":\"ransomware_response\",\"state\":\"%s\",\"detail\":\"%s\"}\n"
        "  ]\n"
        "}\n",
        kill_switch ? "true" : "false",
        policy_version == 0 || kill_switch ? "shadow" : "active",
        response_state,
        response_detail);
    fclose(file);
}

static bool reload_verified_policy(void) {
    NexusPolicyHandle *verified = read_verified_policy();
    if (verified == NULL) {
        os_log_error(g_log,
                     "policy reload rejected; retaining last-known-good policy");
        return false;
    }

    uint64_t candidate_version = nexus_policy_version(verified);
    uint64_t persisted_version = read_policy_watermark();

    pthread_rwlock_wrlock(&g_policy_lock);
    uint64_t current_version =
        g_policy == NULL ? 0 : nexus_policy_version(g_policy);
    uint64_t minimum_version =
        current_version > persisted_version ? current_version : persisted_version;

    if (minimum_version > 0 && candidate_version < minimum_version) {
        pthread_rwlock_unlock(&g_policy_lock);
        nexus_policy_free(verified);
        os_log_error(g_log,
                     "policy downgrade rejected minimum=%{public}llu candidate=%{public}llu",
                     (unsigned long long)minimum_version,
                     (unsigned long long)candidate_version);
        return false;
    }

    NexusPolicyHandle *previous = g_policy;
    g_policy = verified;
    uint64_t version = candidate_version;
    pthread_rwlock_unlock(&g_policy_lock);

    if (previous != NULL) {
        nexus_policy_free(previous);
    }

    if (!write_policy_watermark(version)) {
        os_log_error(g_log,
                     "failed persisting policy version watermark; retaining policy in memory");
    }
    write_health_file();

    os_log(g_log,
           "activated verified endpoint policy version %{public}llu",
           (unsigned long long)version);
    return true;
}

static void set_kill_switch(int signo) {
    (void)signo;
    atomic_store_explicit(&g_kill_switch, true, memory_order_relaxed);
    atomic_store_explicit(&g_reload_requested, true, memory_order_relaxed);
}

static void clear_kill_switch(int signo) {
    (void)signo;
    atomic_store_explicit(&g_kill_switch, false, memory_order_relaxed);
    atomic_store_explicit(&g_reload_requested, true, memory_order_relaxed);
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

    if (g_ransomware_tracker != NULL &&
        (decision == NEXUS_DECISION_DENY || decision == NEXUS_DECISION_ALERT)) {
        pid_t pid = audit_token_to_pid(message->event.exec.target->audit_token);
        (void)nexus_ransomware_mark_suspicious_process(
            g_ransomware_tracker,
            (uint32_t)pid,
            monotonic_ms());
    }

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

static void observe_file_activity(const es_message_t *message) {
    if (message == NULL || message->process == NULL || g_ransomware_tracker == NULL) {
        return;
    }

    const es_file_t *file = NULL;
    bool renamed = false;

    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            file = message->event.write.target;
            break;
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            file = message->event.rename.source;
            renamed = true;
            break;
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            file = message->event.unlink.target;
            break;
        default:
            return;
    }

    if (file == NULL || file->path.data == NULL || file->path.length == 0) {
        return;
    }

    pid_t pid = audit_token_to_pid(message->process->audit_token);
    NexusRansomwareAssessment assessment =
        nexus_ransomware_observe_path(
            g_ransomware_tracker,
            (uint32_t)pid,
            monotonic_ms(),
            (const uint8_t *)file->path.data,
            file->path.length,
            renamed);

    NexusRansomwareResponse response = {
        .matched = false,
        .would_enforce = false,
        .enforce = false,
        .action = 255
    };

    pthread_rwlock_rdlock(&g_policy_lock);
    NexusPolicyHandle *policy = g_policy;
    if (policy != NULL) {
        response = nexus_ransomware_plan_response(
            policy,
            g_ransomware_tracker,
            (uint32_t)pid,
            assessment.score,
            assessment.severity);
    }
    pthread_rwlock_unlock(&g_policy_lock);

    if (assessment.severity >= 2 && assessment.severity != 255) {
        os_log_error(
            g_log,
            "ransomware_behavior pid=%{public}d score=%{public}u severity=%{public}u path=%{public}.*s",
            pid,
            assessment.score,
            assessment.severity,
            (int)file->path.length,
            file->path.data);
    }

    if (response.matched) {
        os_log_error(
            g_log,
            "ransomware_response pid=%{public}d action=%{public}u would_enforce=%{public}s enforce=%{public}s",
            pid,
            response.action,
            response.would_enforce ? "true" : "false",
            response.enforce ? "true" : "false");

        if (response.enforce) {
            if (response.action != 1) {
                os_log_error(
                    g_log,
                    "containment_skipped pid=%{public}d reason=unsupported_action action=%{public}u",
                    pid,
                    response.action);
            } else if (atomic_load_explicit(&g_kill_switch, memory_order_relaxed)) {
                os_log_error(
                    g_log,
                    "containment_skipped pid=%{public}d reason=kill_switch",
                    pid);
            } else if (access(CONTAINMENT_DISABLE_PATH, F_OK) == 0) {
                os_log_error(
                    g_log,
                    "containment_skipped pid=%{public}d reason=local_disable_switch",
                    pid);
            } else if (pid <= 1 || pid == getpid()) {
                os_log_error(
                    g_log,
                    "containment_skipped pid=%{public}d reason=protected_pid",
                    pid);
            } else if (kill(pid, SIGKILL) == 0) {
                os_log_error(
                    g_log,
                    "containment_applied pid=%{public}d action=terminate_process",
                    pid);
            } else {
                os_log_error(
                    g_log,
                    "containment_failed pid=%{public}d errno=%{public}d",
                    pid,
                    errno);
            }
        }
    }
}

static void handle_message(es_client_t *client, const es_message_t *message) {
    if (message == NULL) {
        return;
    }

    if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        handle_auth_exec(client, message);
        return;
    }

    observe_file_activity(message);
}

int main(void) {
    g_log = os_log_create("ai.votal.nexus.agent.endpoint", "endpoint-security");
    ensure_state_directory();
    signal(SIGUSR1, set_kill_switch);
    signal(SIGUSR2, clear_kill_switch);
    signal(SIGHUP, request_policy_reload);

    /*
     * Policy loading and signature verification happen before ES subscription.
     * Verification failure leaves g_policy NULL, which makes every callback
     * fail open.
     */
    (void)reload_verified_policy();

    g_ransomware_tracker = nexus_ransomware_tracker_new(5000, 4096);
    if (g_ransomware_tracker == NULL) {
        os_log_error(g_log, "ransomware tracker unavailable; continuing without behavior correlation");
    }

    es_client_t *client = NULL;
    es_new_client_result_t result =
        es_new_client(&client, ^(es_client_t *callback_client, const es_message_t *message) {
            handle_message(callback_client, message);
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        os_log_error(g_log, "es_new_client failed: %{public}d", result);
        if (g_policy != NULL) {
            nexus_policy_free(g_policy);
            g_policy = NULL;
        }
        if (g_ransomware_tracker != NULL) {
            nexus_ransomware_tracker_free(g_ransomware_tracker);
            g_ransomware_tracker = NULL;
        }
        return EXIT_FAILURE;
    }

    const es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK
    };
    if (es_subscribe(
            client,
            events,
            sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        os_log_error(g_log, "es_subscribe failed");
        es_delete_client(client);
        if (g_policy != NULL) {
            nexus_policy_free(g_policy);
            g_policy = NULL;
        }
        if (g_ransomware_tracker != NULL) {
            nexus_ransomware_tracker_free(g_ransomware_tracker);
            g_ransomware_tracker = NULL;
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
            write_health_file();
        }
    });
    dispatch_resume(reload_timer);

    pthread_rwlock_rdlock(&g_policy_lock);
    bool policy_loaded = g_policy != NULL;
    pthread_rwlock_unlock(&g_policy_lock);

    write_health_file();

    os_log(g_log,
           "Nexus Endpoint Security extension started; policy_loaded=%{public}s; SIGHUP reloads policy",
           policy_loaded ? "true" : "false");
    dispatch_main();
    return EXIT_SUCCESS;
}
