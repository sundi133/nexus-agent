#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_DENY_RULES 64
#define MAX_PATH_BYTES 4096

typedef enum {
    MODE_AUDIT = 0,
    MODE_ENFORCE = 1,
} enforcement_mode_t;

typedef struct {
    enforcement_mode_t mode;
    size_t deny_rule_count;
    char deny_exec[MAX_DENY_RULES][MAX_PATH_BYTES];
} local_policy_t;

static es_client_t *g_client = NULL;
static local_policy_t g_policy;
static atomic_bool g_kill_switch = false;
static atomic_ullong g_decision_count = 0;
static atomic_ullong g_deny_count = 0;
static atomic_ullong g_fail_open_count = 0;

static uint64_t monotonic_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return ((uint64_t)ts.tv_sec * 1000000ULL) + ((uint64_t)ts.tv_nsec / 1000ULL);
}

static char *token_copy(es_string_token_t token) {
    char *result = calloc(token.length + 1, 1);
    if (result == NULL) return NULL;
    if (token.length > 0 && token.data != NULL) {
        memcpy(result, token.data, token.length);
    }
    return result;
}

static void trim_newline(char *line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
}

static bool load_policy(const char *path, local_policy_t *policy) {
    memset(policy, 0, sizeof(*policy));
    policy->mode = MODE_AUDIT;

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return false;
    }

    char line[MAX_PATH_BYTES + 64];
    bool valid = true;

    while (fgets(line, sizeof(line), file) != NULL) {
        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        if (strncmp(line, "mode=", 5) == 0) {
            const char *value = line + 5;
            if (strcmp(value, "audit") == 0) {
                policy->mode = MODE_AUDIT;
            } else if (strcmp(value, "enforce") == 0) {
                policy->mode = MODE_ENFORCE;
            } else {
                valid = false;
                break;
            }
            continue;
        }

        if (strncmp(line, "deny_exec=", 10) == 0) {
            const char *value = line + 10;
            size_t len = strlen(value);
            if (len == 0 || len >= MAX_PATH_BYTES ||
                policy->deny_rule_count >= MAX_DENY_RULES) {
                valid = false;
                break;
            }
            memcpy(policy->deny_exec[policy->deny_rule_count], value, len + 1);
            policy->deny_rule_count++;
            continue;
        }

        valid = false;
        break;
    }

    fclose(file);
    return valid;
}

static bool policy_denies_exec(const local_policy_t *policy, const char *path) {
    if (path == NULL) return false;
    for (size_t i = 0; i < policy->deny_rule_count; ++i) {
        if (strcmp(policy->deny_exec[i], path) == 0) {
            return true;
        }
    }
    return false;
}

static void respond_allow(es_client_t *client, const es_message_t *message, bool fail_open) {
    if (fail_open) {
        atomic_fetch_add_explicit(&g_fail_open_count, 1, memory_order_relaxed);
    }
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
}

static void handle_auth_exec(es_client_t *client, const es_message_t *message) {
    const uint64_t started_us = monotonic_us();
    atomic_fetch_add_explicit(&g_decision_count, 1, memory_order_relaxed);

    if (atomic_load_explicit(&g_kill_switch, memory_order_relaxed)) {
        respond_allow(client, message, true);
        fprintf(stderr, "nexus-es-auth-enforce: action=allow reason=kill_switch\n");
        return;
    }

    if (message == NULL || message->event.exec.target == NULL ||
        message->event.exec.target->executable == NULL) {
        if (message != NULL) {
            respond_allow(client, message, true);
        }
        fprintf(stderr, "nexus-es-auth-enforce: action=allow reason=missing_target fail_open=true\n");
        return;
    }

    char *path = token_copy(message->event.exec.target->executable->path);
    if (path == NULL) {
        respond_allow(client, message, true);
        fprintf(stderr, "nexus-es-auth-enforce: action=allow reason=allocation_failure fail_open=true\n");
        return;
    }

    const bool matched = policy_denies_exec(&g_policy, path);
    es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
    const char *reason = "no_matching_rule";

    if (matched && g_policy.mode == MODE_ENFORCE) {
        result = ES_AUTH_RESULT_DENY;
        reason = "exact_path_deny";
        atomic_fetch_add_explicit(&g_deny_count, 1, memory_order_relaxed);
    } else if (matched) {
        reason = "audit_would_deny";
    }

    es_return_t response = es_respond_auth_result(client, message, result, false);
    const uint64_t finished_us = monotonic_us();
    const uint64_t latency_us =
        finished_us >= started_us ? finished_us - started_us : 0;

    if (response != ES_RETURN_SUCCESS) {
        fprintf(stderr,
                "nexus-es-auth-enforce: response_failed target=%s requested=%s latency_us=%llu\n",
                path,
                result == ES_AUTH_RESULT_DENY ? "deny" : "allow",
                (unsigned long long)latency_us);
    } else {
        fprintf(stderr,
                "nexus-es-auth-enforce: pid=%d target=%s matched=%s mode=%s action=%s reason=%s latency_us=%llu decisions=%llu denies=%llu fail_open=%llu\n",
                audit_token_to_pid(message->process->audit_token),
                path,
                matched ? "true" : "false",
                g_policy.mode == MODE_ENFORCE ? "enforce" : "audit",
                result == ES_AUTH_RESULT_DENY ? "deny" : "allow",
                reason,
                (unsigned long long)latency_us,
                (unsigned long long)atomic_load_explicit(&g_decision_count, memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_deny_count, memory_order_relaxed),
                (unsigned long long)atomic_load_explicit(&g_fail_open_count, memory_order_relaxed));
    }

    free(path);
}

static void kill_switch_on(int signo) {
    (void)signo;
    atomic_store_explicit(&g_kill_switch, true, memory_order_relaxed);
}

static void kill_switch_off(int signo) {
    (void)signo;
    atomic_store_explicit(&g_kill_switch, false, memory_order_relaxed);
}

static void shutdown_handler(int signo) {
    (void)signo;
    if (g_client != NULL) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
        g_client = NULL;
    }
    _Exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <local-policy.conf>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (!load_policy(argv[1], &g_policy)) {
        fprintf(stderr,
                "nexus-es-auth-enforce: invalid/unreadable policy; refusing to start enforcement\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);
    signal(SIGUSR1, kill_switch_on);
    signal(SIGUSR2, kill_switch_off);

    es_new_client_result_t result =
        es_new_client(&g_client, ^(es_client_t *client, const es_message_t *message) {
            if (message != NULL && message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
                handle_auth_exec(client, message);
            }
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "nexus-es-auth-enforce: es_new_client failed (%d)\n", result);
        return EXIT_FAILURE;
    }

    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "nexus-es-auth-enforce: es_subscribe failed\n");
        es_delete_client(g_client);
        g_client = NULL;
        return EXIT_FAILURE;
    }

    fprintf(stderr,
            "nexus-es-auth-enforce: active mode=%s deny_rules=%zu; "
            "SIGUSR1 enables kill switch (allow all), SIGUSR2 disables it\n",
            g_policy.mode == MODE_ENFORCE ? "enforce" : "audit",
            g_policy.deny_rule_count);

    dispatch_main();
    return EXIT_SUCCESS;
}
