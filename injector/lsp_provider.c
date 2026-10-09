/*
 * LSP Provider DLL — ws2_32.dll tarafindan yuklenir
 *
 * Bu DLL Winsock Catalog'a kaydedildikten sonra,
 * herhangi bir process socket() cagirdiginda ws2_32.dll
 * bu DLL'i otomatik yukler.
 *
 * KnightOnLine.exe icinde yuklendiginde payload baslatilir.
 * Diger process'lerde sadece seffaf proxy olarak calisir.
 *
 * Winsock LSP chain:
 *   Uygulama → ws2_32.dll → [bizim LSP] → base provider (mswsock.dll)
 *
 * Tum socket operasyonlari seffaf olarak iletilir.
 * Ek gecikme: ~0 (sadece fonksiyon pointer indirection)
 */

#include <windows.h>
#include <ws2spi.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

static WSPPROC_TABLE g_nextTable;
static WSPUPCALLTABLE g_upCallTable;
static BOOL g_payloadLoaded = FALSE;
static HMODULE g_payloadModule = NULL;

typedef void (*pfn_payload_startup)(HMODULE);
typedef void (*pfn_payload_shutdown)(void);

static BOOL is_target_process(void)
{
    char exeName[MAX_PATH];
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    _strlwr(exeName);
    return (strstr(exeName, "knightonline") != NULL ||
            strstr(exeName, "knight") != NULL);
}

static void try_load_payload(void)
{
    if (g_payloadLoaded) return;
    if (!is_target_process()) return;

    char dllDir[MAX_PATH];
    HMODULE self;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)try_load_payload, &self);

    GetModuleFileNameA(self, dllDir, MAX_PATH);
    char *slash = strrchr(dllDir, '\\');
    if (slash) *(slash + 1) = '\0';

    char payloadPath[MAX_PATH];
    snprintf(payloadPath, MAX_PATH, "%spayload.dll", dllDir);

    if (GetFileAttributesA(payloadPath) == INVALID_FILE_ATTRIBUTES) {
        GetTempPathA(MAX_PATH, payloadPath);
        strcat(payloadPath, "payload.dll");
    }

    if (GetFileAttributesA(payloadPath) == INVALID_FILE_ATTRIBUTES)
        return;

    g_payloadModule = LoadLibraryA(payloadPath);
    if (!g_payloadModule) return;

    pfn_payload_startup startup =
        (pfn_payload_startup)GetProcAddress(g_payloadModule, "payload_startup");

    if (startup) {
        startup(g_payloadModule);
        g_payloadLoaded = TRUE;
    }
}

static void try_unload_payload(void)
{
    if (!g_payloadLoaded || !g_payloadModule) return;

    pfn_payload_shutdown shutdown =
        (pfn_payload_shutdown)GetProcAddress(g_payloadModule, "payload_shutdown");
    if (shutdown) shutdown();

    g_payloadLoaded = FALSE;
}

/*
 * WSPStartup — ws2_32.dll bu fonksiyonu cagirarak LSP'yi baslatir
 *
 * Gorevimiz: alt katman provider'i bul, onun WSPStartup'ini cagir,
 * fonksiyon tablosunu al, ve ws2_32'ye dondur.
 */
int WSPAPI WSPStartup(
    WORD wVersionRequested,
    LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE upcallTable,
    LPWSPPROC_TABLE lpProcTable)
{
    g_upCallTable = upcallTable;

    if (lpProtocolInfo->ProtocolChain.ChainLen <= 1) {
        return WSAEPROVIDERFAILEDINIT;
    }

    DWORD nextCatalogId = lpProtocolInfo->ProtocolChain.ChainEntries[1];

    DWORD bufLen = 0;
    int err = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);

    LPWSAPROTOCOL_INFOW protos = (LPWSAPROTOCOL_INFOW)malloc(bufLen);
    int count = WSCEnumProtocols(NULL, protos, &bufLen, &err);

    WSAPROTOCOL_INFOW *nextProto = NULL;
    for (int i = 0; i < count; i++) {
        if (protos[i].dwCatalogEntryId == nextCatalogId) {
            nextProto = &protos[i];
            break;
        }
    }

    if (!nextProto) {
        free(protos);
        return WSAEPROVIDERFAILEDINIT;
    }

    wchar_t nextDllPath[MAX_PATH] = {0};
    int pathLen = MAX_PATH;
    WSCGetProviderPath(&nextProto->ProviderId, nextDllPath, &pathLen, &err);

    wchar_t expandedPath[MAX_PATH];
    ExpandEnvironmentStringsW(nextDllPath, expandedPath, MAX_PATH);

    HMODULE hNext = LoadLibraryW(expandedPath);
    if (!hNext) {
        free(protos);
        return WSAEPROVIDERFAILEDINIT;
    }

    LPWSPSTARTUP pfnWSPStartup =
        (LPWSPSTARTUP)GetProcAddress(hNext, "WSPStartup");
    if (!pfnWSPStartup) {
        FreeLibrary(hNext);
        free(protos);
        return WSAEPROVIDERFAILEDINIT;
    }

    WSAPROTOCOL_INFOW nextInfo;
    memcpy(&nextInfo, nextProto, sizeof(WSAPROTOCOL_INFOW));
    free(protos);

    int ret = pfnWSPStartup(wVersionRequested, lpWSPData,
                            &nextInfo, upcallTable, lpProcTable);

    if (ret == 0) {
        memcpy(&g_nextTable, lpProcTable, sizeof(WSPPROC_TABLE));
    }

    try_load_payload();

    return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        try_unload_payload();
        break;
    }
    return TRUE;
}
