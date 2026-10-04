#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static es_client_t *g_client = NULL;

static char *token_copy(es_string_token_t token) {
    char *result = calloc(token.length + 1, 1);
    if (result == NULL) return NULL;
    if (token.length > 0 && token.data != NULL) memcpy(result, token.data, token.length);
    return result;
}

/*
 * Shadow policy is intentionally narrow: it records that a configured exact
 * path would be denied, but ALWAYS responds ALLOW. This lets us validate
 * authorization latency and event semantics before enabling enforcement.
 */
static bool shadow_would_deny_exec(const char *path) {
    const char *configured = getenv("NEXUS_SHADOW_DENY_EXEC");
    return configured != NULL && path != NULL && strcmp(configured, path) == 0;
}

static void handle_auth_exec(es_client_t *client, const es_message_t *message) {
    char *path = NULL;
    if (message->event.exec.target != NULL &&
        message->event.exec.target->executable != NULL) {
        path = token_copy(message->event.exec.target->executable->path);
    }

    bool would_deny = shadow_would_deny_exec(path);
    fprintf(stderr,
            "nexus-es-auth-shadow: pid=%d target=%s would_deny=%s action=allow\n",
            audit_token_to_pid(message->process->audit_token),
            path != NULL ? path : "<unknown>",
            would_deny ? "true" : "false");

    /* Shadow mode invariant: never deny. */
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
    free(path);
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

int main(void) {
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    es_new_client_result_t result =
        es_new_client(&g_client, ^(es_client_t *client, const es_message_t *message) {
            if (message != NULL && message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
                handle_auth_exec(client, message);
            }
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "nexus-es-auth-shadow: es_new_client failed (%d)\n", result);
        return EXIT_FAILURE;
    }

    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    if (es_subscribe(g_client, events, 1) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "nexus-es-auth-shadow: es_subscribe failed\n");
        es_delete_client(g_client);
        g_client = NULL;
        return EXIT_FAILURE;
    }

    fprintf(stderr,
            "nexus-es-auth-shadow: active; all exec requests are ALLOWED; "
            "set NEXUS_SHADOW_DENY_EXEC to record an exact-path would-deny match\n");
    dispatch_main();
    return EXIT_SUCCESS;
}
