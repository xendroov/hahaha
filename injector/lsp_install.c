/*
 * Winsock LSP (Layered Service Provider) Injection
 *
 * En derin injection vektoru. OS kernel'i inject ediyor, biz degil.
 *
 * Neden XIGNCODE bunu ASLA gormez:
 *   - LSP DLL'leri ws2_32.dll tarafindan yuklenir (isletim sistemi)
 *   - Winsock Catalog bir sistem veritabani, anti-cheat kontrol etmez
 *   - KO online oyun, %100 socket kullanir → LSP'miz yuklenir
 *   - CreateRemoteThread yok, LoadLibrary yok, hook yok
 *   - DLL yuklenmesi isletim sistemi seviyesinde, user-mode gorunmuyor
 *
 * Mimari:
 *   Bu dosya IKI arac icerir:
 *
 *   1. LSP Installer (lsp_install.exe):
 *      - Winsock Catalog'a bizim LSP DLL'imizi kaydeder
 *      - WSCInstallProvider API kullanir
 *      - Admin yetkisi gerektirir
 *      - Bir kez calistirilir, sonra her socket uygulamasi LSP'yi yukler
 *
 *   2. LSP DLL (ayri olarak derlenir — lsp_provider.c):
 *      - ws2_32.dll tarafindan otomatik yuklenir
 *      - Gercek Winsock provider'a chain eder (seffaf proxy)
 *      - KnightOnLine.exe icindeyse payload'u baslatir
 *      - Diger process'lerde sessiz kalir
 *
 * Kullanim:
 *   lsp_install.exe install [lsp_provider.dll yolu]
 *   lsp_install.exe remove
 *   lsp_install.exe status
 *
 * Not: LSP Windows Vista+ uzerinde calismaya devam eder.
 *      WFP (Windows Filtering Platform) LSP'nin yerini almadi,
 *      sadece kernel-mode filtreleme ekledi.
 */

#include <windows.h>
#include <ws2spi.h>
#include <sporder.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

// {A7B2C9D4-E5F6-4A3B-8C1D-2E3F4A5B6C7D}
static const GUID LSP_GUID = {
    0xA7B2C9D4, 0xE5F6, 0x4A3B,
    {0x8C, 0x1D, 0x2E, 0x3F, 0x4A, 0x5B, 0x6C, 0x7D}
};

static void print_catalog(void)
{
    DWORD bufLen = 0;
    int err = 0;

    WSCEnumProtocols(NULL, NULL, &bufLen, &err);
    if (bufLen == 0) {
        printf("[*] Winsock Catalog bos\n");
        return;
    }

    LPWSAPROTOCOL_INFOW protos = (LPWSAPROTOCOL_INFOW)malloc(bufLen);
    int count = WSCEnumProtocols(NULL, protos, &bufLen, &err);

    printf("[*] Winsock Catalog (%d entry):\n", count);
    for (int i = 0; i < count; i++) {
        wchar_t path[MAX_PATH] = {0};
        int pathLen = MAX_PATH;
        WSCGetProviderPath(&protos[i].ProviderId, path, &pathLen, &err);

        BOOL isOurs = memcmp(&protos[i].ProviderId, &LSP_GUID,
                             sizeof(GUID)) == 0;

        printf("  [%d] CatId=%d %S%s\n",
               i,
               protos[i].dwCatalogEntryId,
               protos[i].szProtocol,
               isOurs ? " <-- BIZIM LSP" : "");

        if (isOurs) {
            printf("       DLL: %S\n", path);
        }
    }

    free(protos);
}

static BOOL install_lsp(const char *dllPath)
{
    char fullPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, fullPath, NULL);

    if (GetFileAttributesA(fullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] LSP DLL bulunamadi: %s\n", fullPath);
        return FALSE;
    }

    wchar_t wFullPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, fullPath, -1, wFullPath, MAX_PATH);

    printf("[*] LSP DLL: %s\n", fullPath);

    DWORD bufLen = 0;
    int err = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);

    LPWSAPROTOCOL_INFOW protos = (LPWSAPROTOCOL_INFOW)malloc(bufLen);
    int count = WSCEnumProtocols(NULL, protos, &bufLen, &err);

    DWORD baseCatalogId = 0;
    WSAPROTOCOL_INFOW baseProto = {0};

    for (int i = 0; i < count; i++) {
        if (protos[i].iAddressFamily == AF_INET &&
            protos[i].iSocketType == SOCK_STREAM &&
            protos[i].iProtocol == IPPROTO_TCP &&
            protos[i].ProtocolChain.ChainLen == 1) {
            baseCatalogId = protos[i].dwCatalogEntryId;
            memcpy(&baseProto, &protos[i], sizeof(WSAPROTOCOL_INFOW));
            printf("[+] Base TCP provider: CatId=%d\n", baseCatalogId);
            break;
        }
    }

    free(protos);

    if (!baseCatalogId) {
        printf("[!] Base TCP provider bulunamadi\n");
        return FALSE;
    }

    WSAPROTOCOL_INFOW lspProto;
    memcpy(&lspProto, &baseProto, sizeof(WSAPROTOCOL_INFOW));
    lspProto.dwServiceFlags1 |= XP1_IFS_HANDLES;
    wcscpy(lspProto.szProtocol, L"KO Research LSP");

    lspProto.ProtocolChain.ChainLen = 2;
    lspProto.ProtocolChain.ChainEntries[1] = baseCatalogId;

    int result = WSCInstallProvider(
        &LSP_GUID,
        wFullPath,
        &lspProto,
        1,
        &err
    );

    if (result == SOCKET_ERROR) {
        printf("[!] WSCInstallProvider basarisiz (err=%d)\n", err);
        if (err == WSANO_RECOVERY)
            printf("[*] Admin yetkisi gerekli! Sag tik → Yonetici olarak calistir\n");
        return FALSE;
    }

    printf("[+] LSP kuruldu (GUID: A7B2C9D4-...)\n");

    bufLen = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);
    protos = (LPWSAPROTOCOL_INFOW)malloc(bufLen);
    count = WSCEnumProtocols(NULL, protos, &bufLen, &err);

    DWORD lspCatalogId = 0;
    for (int i = 0; i < count; i++) {
        if (memcmp(&protos[i].ProviderId, &LSP_GUID, sizeof(GUID)) == 0) {
            lspCatalogId = protos[i].dwCatalogEntryId;
            break;
        }
    }

    if (lspCatalogId) {
        DWORD *order = (DWORD *)malloc(count * sizeof(DWORD));
        int orderIdx = 0;

        order[orderIdx++] = lspCatalogId;

        for (int i = 0; i < count; i++) {
            if (protos[i].dwCatalogEntryId != lspCatalogId)
                order[orderIdx++] = protos[i].dwCatalogEntryId;
        }

        int orderResult = WSCWriteProviderOrder(order, orderIdx);
        if (orderResult == 0)
            printf("[+] LSP catalog sirasina yerlestirildi (1. sirada)\n");
        else
            printf("[*] Sira ayarlanamadi (err=%d) — yine de calisabilir\n",
                   WSAGetLastError());

        free(order);
    }

    free(protos);
    return TRUE;
}

static BOOL remove_lsp(void)
{
    int err = 0;
    int result = WSCDeinstallProvider(&LSP_GUID, &err);

    if (result == SOCKET_ERROR) {
        if (err == WSAEINVAL) {
            printf("[*] LSP zaten kayitli degil\n");
            return TRUE;
        }
        printf("[!] WSCDeinstallProvider basarisiz (err=%d)\n", err);
        return FALSE;
    }

    printf("[+] LSP kaldirildi\n");
    return TRUE;
}

int main(int argc, char *argv[])
{
    printf("=== Winsock LSP Injection Tool ===\n");
    printf("    OS inject eder, biz degil\n\n");

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (argc < 2) {
        printf("Kullanim:\n");
        printf("  lsp_install.exe install [lsp_provider.dll]\n");
        printf("  lsp_install.exe remove\n");
        printf("  lsp_install.exe status\n\n");
        printf("install: LSP'yi Winsock Catalog'a kaydeder\n");
        printf("         Sonra KO her basladiginda OS otomatik yukler\n");
        printf("remove:  LSP'yi Catalog'dan siler\n");
        printf("status:  Mevcut Winsock Catalog'u goster\n");
        WSACleanup();
        return 1;
    }

    if (_stricmp(argv[1], "status") == 0) {
        print_catalog();
    }
    else if (_stricmp(argv[1], "install") == 0) {
        const char *dllPath = (argc > 2) ? argv[2] : "lsp_provider.dll";
        if (install_lsp(dllPath))
            printf("\n[+] BASARILI. Artik her socket uygulamasi LSP'yi yukler.\n");
        else
            printf("\n[!] BASARISIZ\n");
    }
    else if (_stricmp(argv[1], "remove") == 0) {
        if (remove_lsp()) {
            printf("[+] Temizlendi. Yeni process'ler LSP yuklemeyecek.\n");
            printf("[*] Mevcut process'lerde LSP bellekte kalmaya devam eder.\n");
        }
    }
    else {
        printf("[!] Bilinmeyen komut: %s\n", argv[1]);
    }

    WSACleanup();
    return 0;
}
