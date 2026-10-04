#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static es_client_t *g_client = NULL;

#define EVENT_QUEUE_CAPACITY 4096

typedef struct {
    es_event_type_t type;
    pid_t pid;
    pid_t ppid;
    char *exec_path;
    char *target_path;
    char *target_name;
} queued_event_t;

static queued_event_t g_queue[EVENT_QUEUE_CAPACITY];
static size_t g_queue_head = 0;
static size_t g_queue_tail = 0;
static size_t g_queue_count = 0;
static dispatch_queue_t g_queue_lock;
static dispatch_queue_t g_worker_queue;
static atomic_ullong g_dropped_events = 0;

static void free_queued_event(queued_event_t *event) {
    free(event->exec_path);
    free(event->target_path);
    free(event->target_name);
    memset(event, 0, sizeof(*event));
}

static bool queue_push(queued_event_t *event) {
    __block bool accepted = false;
    dispatch_sync(g_queue_lock, ^{
        if (g_queue_count < EVENT_QUEUE_CAPACITY) {
            g_queue[g_queue_tail] = *event;
            g_queue_tail = (g_queue_tail + 1) % EVENT_QUEUE_CAPACITY;
            g_queue_count++;
            accepted = true;
        }
    });
    if (!accepted) {
        atomic_fetch_add_explicit(&g_dropped_events, 1, memory_order_relaxed);
    }
    return accepted;
}

static bool queue_pop(queued_event_t *event) {
    __block bool found = false;
    dispatch_sync(g_queue_lock, ^{
        if (g_queue_count > 0) {
            *event = g_queue[g_queue_head];
            memset(&g_queue[g_queue_head], 0, sizeof(g_queue[g_queue_head]));
            g_queue_head = (g_queue_head + 1) % EVENT_QUEUE_CAPACITY;
            g_queue_count--;
            found = true;
        }
    });
    return found;
}

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

static void emit_queued_event(queued_event_t *event) {
    fputs("{\"kind\":", stdout);
    json_string(event_name(event->type));
    fprintf(stdout, ",\"pid\":%d,\"parent_pid\":%d,\"executable_path\":",
            event->pid, event->ppid);
    if (event->exec_path) json_string(event->exec_path); else fputs("null", stdout);
    if (event->target_path) {
        fputs(",\"target_path\":", stdout);
        json_string(event->target_path);
    }
    if (event->target_name) {
        fputs(",\"target_name\":", stdout);
        json_string(event->target_name);
    }
    fprintf(stdout, ",\"collector_dropped_events\":%llu}\n",
            atomic_load_explicit(&g_dropped_events, memory_order_relaxed));
    fflush(stdout);
}

static void drain_events(void) {
    queued_event_t event;
    while (queue_pop(&event)) {
        emit_queued_event(&event);
        free_queued_event(&event);
    }
}

static void enqueue_message(const es_message_t *message) {
    queued_event_t event = {
        .type = message->event_type,
        .pid = audit_token_to_pid(message->process->audit_token),
        .ppid = message->process->ppid,
        .exec_path = process_path(message->process),
        .target_path = NULL,
        .target_name = NULL,
    };

    switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            event.target_path =
                token_copy(message->event.create.destination.new_path.dir->path);
            event.target_name =
                token_copy(message->event.create.destination.new_path.filename);
            break;
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            event.target_path = token_copy(message->event.unlink.target->path);
            break;
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            event.target_path = token_copy(message->event.rename.source->path);
            break;
        default:
            break;
    }

    if (!queue_push(&event)) {
        free_queued_event(&event);
        return;
    }
    dispatch_async(g_worker_queue, ^{
        drain_events();
    });
}

static void handle_message(es_client_t *client, const es_message_t *message) {
    (void)client;
    if (message == NULL || message->process == NULL) {
        return;
    }
    enqueue_message(message);
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
    g_queue_lock = dispatch_queue_create("ai.votal.nexus.queue-lock", DISPATCH_QUEUE_SERIAL);
    g_worker_queue = dispatch_queue_create("ai.votal.nexus.worker", DISPATCH_QUEUE_SERIAL);

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
