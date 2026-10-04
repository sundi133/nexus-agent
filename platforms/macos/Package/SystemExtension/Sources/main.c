#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <os/log.h>
#include <stdlib.h>

static os_log_t nexus_log;

static void handle_message(es_client_t *client, const es_message_t *message) {
    if (message == NULL) {
        return;
    }

    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
            /*
             * Packaging milestone invariant: the installed system extension is
             * fail-safe allow-only until verified signed policy integration is
             * linked into this target.
             */
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
            break;
        default:
            break;
    }
}

int main(void) {
    nexus_log = os_log_create("ai.votal.nexus.agent.endpoint", "endpoint-security");

    es_client_t *client = NULL;
    es_new_client_result_t result =
        es_new_client(&client, ^(es_client_t *callback_client, const es_message_t *message) {
            handle_message(callback_client, message);
        });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        os_log_error(nexus_log, "es_new_client failed: %{public}d", result);
        return EXIT_FAILURE;
    }

    const es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    if (es_subscribe(client, events, 1) != ES_RETURN_SUCCESS) {
        os_log_error(nexus_log, "es_subscribe failed");
        es_delete_client(client);
        return EXIT_FAILURE;
    }

    os_log(nexus_log, "Nexus Endpoint Security system extension started in allow-only packaging mode");
    dispatch_main();
    return EXIT_SUCCESS;
}
