#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static es_client_t *g_client = NULL;

static void json_string(const char *value) {
    putchar('"');
    if (value != NULL) {
        for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
            switch (*p) {
                case '"': fputs("\\\"", stdout); break;
                case '\\': fputs("\\\\", stdout); break;
                case '\n': fputs("\\n", stdout); break;
                case '\r': fputs("\\r", stdout); break;
                case '\t': fputs("\\t", stdout); break;
                default:
                    if (*p < 0x20) {
                        fprintf(stdout, "\\u%04x", *p);
                    } else {
                        putchar(*p);
                    }
            }
        }
    }
    putchar('"');
}

static char *token_copy(es_string_token_t token) {
    char *result = calloc(token.length + 1, 1);
    if (result == NULL) {
        return NULL;
    }
    if (token.length > 0 && token.data != NULL) {
        memcpy(result, token.data, token.length);
    }
    return result;
}

static const char *event_name(es_event_type_t type) {
    switch (type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC: return "process_exec";
        case ES_EVENT_TYPE_NOTIFY_FORK: return "process_fork";
        case ES_EVENT_TYPE_NOTIFY_EXIT: return "process_exit";
        case ES_EVENT_TYPE_NOTIFY_CREATE: return "file_create";
        case ES_EVENT_TYPE_NOTIFY_RENAME: return "file_rename";
        case ES_EVENT_TYPE_NOTIFY_UNLINK: return "file_delete";
        default: return "unknown";
    }
}

static char *process_path(const es_process_t *process) {
    if (process == NULL || process->executable == NULL) {
        return NULL;
    }
    return token_copy(process->executable->path);
}

static void emit_event(const es_message_t *message) {
    pid_t pid = audit_token_to_pid(message->process->audit_token);
    pid_t ppid = message->process->ppid;
    char *exec_path = process_path(message->process);

    fputs("{\"kind\":", stdout);
    json_string(event_name(message->event_type));
    fprintf(stdout, ",\"pid\":%d,\"parent_pid\":%d,\"executable_path\":", pid, ppid);
    if (exec_path != NULL) json_string(exec_path); else fputs("null", stdout);

    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_CREATE: {
            char *path = token_copy(message->event.create.destination.new_path.dir->path);
            char *name = token_copy(message->event.create.destination.new_path.filename);
            fputs(",\"target_directory\":", stdout);
            if (path) json_string(path); else fputs("null", stdout);
            fputs(",\"target_name\":", stdout);
            if (name) json_string(name); else fputs("null", stdout);
            free(path);
            free(name);
            break;
        }
        case ES_EVENT_TYPE_NOTIFY_UNLINK: {
            char *path = token_copy(message->event.unlink.target->path);
            fputs(",\"target_path\":", stdout);
            if (path) json_string(path); else fputs("null", stdout);
            free(path);
            break;
        }
        case ES_EVENT_TYPE_NOTIFY_RENAME: {
            char *source = token_copy(message->event.rename.source->path);
            fputs(",\"source_path\":", stdout);
            if (source) json_string(source); else fputs("null", stdout);
            free(source);
            break;
        }
        default:
            break;
    }

    fputs("}\n", stdout);
    fflush(stdout);
    free(exec_path);
}

static void handle_message(es_client_t *client, const es_message_t *message) {
    (void)client;
    if (message == NULL || message->process == NULL) {
        return;
    }
    emit_event(message);
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

static const char *new_client_error(es_new_client_result_t result) {
    switch (result) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "not entitled";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "not permitted";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "not privileged";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "too many Endpoint Security clients";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "internal Endpoint Security error";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "invalid argument";
        default: return "unknown error";
    }
}

int main(void) {
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    es_new_client_result_t result = es_new_client(&g_client, ^(es_client_t *client, const es_message_t *message) {
        handle_message(client, message);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "nexus-es-collector: es_new_client failed: %s (%d)\n",
                new_client_error(result), result);
        return EXIT_FAILURE;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
    };

    es_return_t subscribe_result =
        es_subscribe(g_client, events, sizeof(events) / sizeof(events[0]));
    if (subscribe_result != ES_RETURN_SUCCESS) {
        fprintf(stderr, "nexus-es-collector: es_subscribe failed (%d)\n", subscribe_result);
        es_delete_client(g_client);
        g_client = NULL;
        return EXIT_FAILURE;
    }

    fprintf(stderr, "nexus-es-collector: audit collector active; blocking is disabled\n");
    dispatch_main();
    return EXIT_SUCCESS;
}
