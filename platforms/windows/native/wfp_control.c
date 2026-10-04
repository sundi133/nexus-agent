#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "rpcrt4.lib")

static const GUID NEXUS_SUBLAYER_KEY =
    {0x7e9b75b2,0xc201,0x4dcf,{0xb4,0xd3,0x7a,0x8e,0x49,0x45,0x91,0x51}};
static const GUID NEXUS_FILTER_KEY =
    {0x9fc593e4,0xe360,0x4e88,{0x95,0x52,0x84,0xb7,0x5e,0xe0,0xa6,0x24}};

static void print_error(const wchar_t *operation, DWORD error) {
    fwprintf(stderr, L"%ls failed: 0x%08lx\n", operation, error);
}

static DWORD open_engine(HANDLE *engine) {
    return FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL,
        engine);
}

static DWORD ensure_sublayer(HANDLE engine) {
    FWPM_SUBLAYER0 sublayer;
    ZeroMemory(&sublayer, sizeof(sublayer));

    sublayer.subLayerKey = NEXUS_SUBLAYER_KEY;
    sublayer.displayData.name = L"Votal Nexus Endpoint";
    sublayer.displayData.description =
        L"Votal Nexus user-mode outbound enforcement test sublayer";
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.weight = 0x100;

    DWORD result = FwpmSubLayerAdd0(engine, &sublayer, NULL);
    if (result == FWP_E_ALREADY_EXISTS) {
        return ERROR_SUCCESS;
    }
    return result;
}

static DWORD parse_ipv4_host_order(const wchar_t *text, UINT32 *address) {
    IN_ADDR parsed;
    ZeroMemory(&parsed, sizeof(parsed));

    if (InetPtonW(AF_INET, text, &parsed) != 1) {
        return ERROR_INVALID_PARAMETER;
    }

    /* WFP FWP_UINT32 IPv4 address conditions use host byte order. */
    *address = ntohl(parsed.S_un.S_addr);
    return ERROR_SUCCESS;
}

static DWORD remove_filter(HANDLE engine) {
    DWORD result = FwpmFilterDeleteByKey0(engine, &NEXUS_FILTER_KEY);
    if (result == FWP_E_FILTER_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    return result;
}

static DWORD remove_all(HANDLE engine) {
    DWORD result = remove_filter(engine);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    result = FwpmSubLayerDeleteByKey0(engine, &NEXUS_SUBLAYER_KEY);
    if (result == FWP_E_SUBLAYER_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    return result;
}

static DWORD install_block(
    HANDLE engine,
    const wchar_t *remote_ipv4,
    const wchar_t *application_path)
{
    UINT32 remote_address = 0;
    DWORD result = parse_ipv4_host_order(remote_ipv4, &remote_address);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    FWP_BYTE_BLOB *app_id = NULL;
    if (application_path != NULL) {
        result = FwpmGetAppIdFromFileName0(application_path, &app_id);
        if (result != ERROR_SUCCESS) {
            return result;
        }
    }

    result = FwpmTransactionBegin0(engine, 0);
    if (result != ERROR_SUCCESS) {
        if (app_id != NULL) {
            FwpmFreeMemory0((void **)&app_id);
        }
        return result;
    }

    BOOL transaction_open = TRUE;

    result = ensure_sublayer(engine);
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = remove_filter(engine);
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    FWPM_FILTER_CONDITION0 conditions[2];
    ZeroMemory(conditions, sizeof(conditions));

    UINT32 condition_count = 0;

    conditions[condition_count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[condition_count].matchType = FWP_MATCH_EQUAL;
    conditions[condition_count].conditionValue.type = FWP_UINT32;
    conditions[condition_count].conditionValue.uint32 = remote_address;
    condition_count++;

    if (app_id != NULL) {
        conditions[condition_count].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[condition_count].matchType = FWP_MATCH_EQUAL;
        conditions[condition_count].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        conditions[condition_count].conditionValue.byteBlob = app_id;
        condition_count++;
    }

    FWPM_FILTER0 filter;
    ZeroMemory(&filter, sizeof(filter));

    filter.filterKey = NEXUS_FILTER_KEY;
    filter.displayData.name = L"Votal Nexus outbound test block";
    filter.displayData.description =
        L"Blocks one exact IPv4 destination for controlled endpoint validation";
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = NEXUS_SUBLAYER_KEY;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = condition_count;
    filter.filterCondition = conditions;
    filter.action.type = FWP_ACTION_BLOCK;

    result = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = FwpmTransactionCommit0(engine);
    if (result == ERROR_SUCCESS) {
        transaction_open = FALSE;
    }

cleanup:
    if (transaction_open) {
        FwpmTransactionAbort0(engine);
    }
    if (app_id != NULL) {
        FwpmFreeMemory0((void **)&app_id);
    }
    return result;
}

static const GUID NEXUS_DYNAMIC_SUBLAYER_KEY =
    {0x2d3b89a2,0x19f9,0x43d5,{0x8e,0x25,0x0f,0x1d,0x9e,0xb1,0x55,0x68}};
static const GUID NEXUS_DYNAMIC_FILTER_KEY =
    {0x5ed76369,0xbcf0,0x4cbc,{0xa0,0x7f,0x63,0xe0,0x2d,0x3a,0x67,0x45}};

typedef struct NEXUS_WFP_SESSION {
    HANDLE engine;
} NEXUS_WFP_SESSION;

static DWORD ensure_dynamic_sublayer(HANDLE engine) {
    FWPM_SUBLAYER0 sublayer;
    ZeroMemory(&sublayer, sizeof(sublayer));

    sublayer.subLayerKey = NEXUS_DYNAMIC_SUBLAYER_KEY;
    sublayer.displayData.name = L"Votal Nexus Runtime";
    sublayer.displayData.description =
        L"Dynamic Votal Nexus service enforcement sublayer";
    sublayer.weight = 0x101;

    DWORD result = FwpmSubLayerAdd0(engine, &sublayer, NULL);
    if (result == FWP_E_ALREADY_EXISTS) {
        return ERROR_SUCCESS;
    }
    return result;
}

static DWORD dynamic_remove_filter(HANDLE engine) {
    DWORD result = FwpmFilterDeleteByKey0(engine, &NEXUS_DYNAMIC_FILTER_KEY);
    if (result == FWP_E_FILTER_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    return result;
}

DWORD nexus_wfp_session_open(void **session_out) {
    if (session_out == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    *session_out = NULL;

    NEXUS_WFP_SESSION *session =
        (NEXUS_WFP_SESSION *)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(NEXUS_WFP_SESSION));
    if (session == NULL) {
        return ERROR_OUTOFMEMORY;
    }

    FWPM_SESSION0 fwpm_session;
    ZeroMemory(&fwpm_session, sizeof(fwpm_session));
    fwpm_session.displayData.name = L"Votal Nexus Runtime Session";
    fwpm_session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD result = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &fwpm_session,
        &session->engine);
    if (result != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, session);
        return result;
    }

    result = ensure_dynamic_sublayer(session->engine);
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(session->engine);
        HeapFree(GetProcessHeap(), 0, session);
        return result;
    }

    *session_out = session;
    return ERROR_SUCCESS;
}

DWORD nexus_wfp_session_clear(void *opaque_session) {
    if (opaque_session == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    NEXUS_WFP_SESSION *session = (NEXUS_WFP_SESSION *)opaque_session;
    return dynamic_remove_filter(session->engine);
}

DWORD nexus_wfp_session_install_exact_ipv4(
    void *opaque_session,
    const wchar_t *remote_ipv4,
    const wchar_t *application_path)
{
    if (opaque_session == NULL || remote_ipv4 == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    NEXUS_WFP_SESSION *session = (NEXUS_WFP_SESSION *)opaque_session;

    UINT32 remote_address = 0;
    DWORD result = parse_ipv4_host_order(remote_ipv4, &remote_address);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    FWP_BYTE_BLOB *app_id = NULL;
    if (application_path != NULL) {
        result = FwpmGetAppIdFromFileName0(application_path, &app_id);
        if (result != ERROR_SUCCESS) {
            return result;
        }
    }

    result = dynamic_remove_filter(session->engine);
    if (result != ERROR_SUCCESS) {
        if (app_id != NULL) {
            FwpmFreeMemory0((void **)&app_id);
        }
        return result;
    }

    FWPM_FILTER_CONDITION0 conditions[2];
    ZeroMemory(conditions, sizeof(conditions));
    UINT32 condition_count = 0;

    conditions[condition_count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[condition_count].matchType = FWP_MATCH_EQUAL;
    conditions[condition_count].conditionValue.type = FWP_UINT32;
    conditions[condition_count].conditionValue.uint32 = remote_address;
    condition_count++;

    if (app_id != NULL) {
        conditions[condition_count].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[condition_count].matchType = FWP_MATCH_EQUAL;
        conditions[condition_count].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        conditions[condition_count].conditionValue.byteBlob = app_id;
        condition_count++;
    }

    FWPM_FILTER0 filter;
    ZeroMemory(&filter, sizeof(filter));
    filter.filterKey = NEXUS_DYNAMIC_FILTER_KEY;
    filter.displayData.name = L"Votal Nexus runtime outbound block";
    filter.displayData.description =
        L"Dynamic exact-destination block owned by the Nexus Windows service";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = NEXUS_DYNAMIC_SUBLAYER_KEY;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = condition_count;
    filter.filterCondition = conditions;
    filter.action.type = FWP_ACTION_BLOCK;

    result = FwpmFilterAdd0(session->engine, &filter, NULL, NULL);

    if (app_id != NULL) {
        FwpmFreeMemory0((void **)&app_id);
    }
    return result;
}

void nexus_wfp_session_close(void *opaque_session) {
    if (opaque_session == NULL) {
        return;
    }

    NEXUS_WFP_SESSION *session = (NEXUS_WFP_SESSION *)opaque_session;
    if (session->engine != NULL) {
        FwpmEngineClose0(session->engine);
        session->engine = NULL;
    }
    HeapFree(GetProcessHeap(), 0, session);
}

DWORD nexus_wfp_install_exact_ipv4(
    const wchar_t *remote_ipv4,
    const wchar_t *application_path)
{
    HANDLE engine = NULL;
    DWORD result = open_engine(&engine);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    result = install_block(engine, remote_ipv4, application_path);
    FwpmEngineClose0(engine);
    return result;
}

DWORD nexus_wfp_remove_all(void)
{
    HANDLE engine = NULL;
    DWORD result = open_engine(&engine);
    if (result != ERROR_SUCCESS) {
        return result;
    }

    result = remove_all(engine);
    FwpmEngineClose0(engine);
    return result;
}

#ifndef NEXUS_WFP_LIBRARY
static void usage(const wchar_t *program) {
    fwprintf(stderr,
        L"Usage:\n"
        L"  %ls install <remote-ipv4> [full-application-path]\n"
        L"  %ls remove\n\n"
        L"Run from an elevated console on an isolated test endpoint.\n",
        program,
        program);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    DWORD result = ERROR_SUCCESS;

    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc != 3 && argc != 4) {
            usage(argv[0]);
            return 2;
        }

        result = nexus_wfp_install_exact_ipv4(
            argv[2],
            argc == 4 ? argv[3] : NULL);

        if (result == ERROR_SUCCESS) {
            wprintf(
                L"Installed Nexus WFP block for destination %ls%s\n",
                argv[2],
                argc == 4 ? L" with application condition" : L"");
        }
    } else if (_wcsicmp(argv[1], L"remove") == 0) {
        if (argc != 2) {
            usage(argv[0]);
            return 2;
        }

        result = nexus_wfp_remove_all();
        if (result == ERROR_SUCCESS) {
            wprintf(L"Removed Nexus WFP test filter and sublayer\n");
        }
    } else {
        usage(argv[0]);
        return 2;
    }

    if (result != ERROR_SUCCESS) {
        print_error(L"WFP operation", result);
    }

    return result == ERROR_SUCCESS ? 0 : (int)result;
}

#endif /* NEXUS_WFP_LIBRARY */
