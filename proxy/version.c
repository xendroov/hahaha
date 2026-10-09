// version.dll proxy — Windows DLL arama sirasini kullanarak payload yukle
//
// Windows oncelik sirasi: 1) uygulama dizini  2) System32
// Oyun dizinine version.dll (bu proxy) + payload.dll koyuyoruz.
// OS oyunu baslatinca bizim version.dll'i yukler, biz de:
//   a) Gercek version.dll'i System32'den yukleriz (tum cagrilari iletiriz)
//   b) payload.dll'i yukleriz (tum moduller baslar)
//
// XIGNCODE henuz aktif degil — payload guvende yuklenir.

#include <windows.h>

// Gercek version.dll handle'i
static HMODULE g_realVersion = NULL;
static HMODULE g_payload     = NULL;

// Her export icin fonksiyon isaretcisi
static FARPROC pfn_GetFileVersionInfoA;
static FARPROC pfn_GetFileVersionInfoByHandle;
static FARPROC pfn_GetFileVersionInfoExA;
static FARPROC pfn_GetFileVersionInfoExW;
static FARPROC pfn_GetFileVersionInfoSizeA;
static FARPROC pfn_GetFileVersionInfoSizeExA;
static FARPROC pfn_GetFileVersionInfoSizeExW;
static FARPROC pfn_GetFileVersionInfoSizeW;
static FARPROC pfn_GetFileVersionInfoW;
static FARPROC pfn_VerFindFileA;
static FARPROC pfn_VerFindFileW;
static FARPROC pfn_VerInstallFileA;
static FARPROC pfn_VerInstallFileW;
static FARPROC pfn_VerLanguageNameA;
static FARPROC pfn_VerLanguageNameW;
static FARPROC pfn_VerQueryValueA;
static FARPROC pfn_VerQueryValueW;

// --- Naked forwarder stub'lari (MSVC x86) ---

__declspec(naked) void __stdcall p_GetFileVersionInfoA(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoA] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoByHandle(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoByHandle] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoExA(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoExA] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoExW(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoExW] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoSizeA(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoSizeA] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoSizeExA(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoSizeExA] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoSizeExW(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoSizeExW] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoSizeW(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoSizeW] } }

__declspec(naked) void __stdcall p_GetFileVersionInfoW(void)
{ __asm { jmp dword ptr [pfn_GetFileVersionInfoW] } }

__declspec(naked) void __stdcall p_VerFindFileA(void)
{ __asm { jmp dword ptr [pfn_VerFindFileA] } }

__declspec(naked) void __stdcall p_VerFindFileW(void)
{ __asm { jmp dword ptr [pfn_VerFindFileW] } }

__declspec(naked) void __stdcall p_VerInstallFileA(void)
{ __asm { jmp dword ptr [pfn_VerInstallFileA] } }

__declspec(naked) void __stdcall p_VerInstallFileW(void)
{ __asm { jmp dword ptr [pfn_VerInstallFileW] } }

__declspec(naked) void __stdcall p_VerLanguageNameA(void)
{ __asm { jmp dword ptr [pfn_VerLanguageNameA] } }

__declspec(naked) void __stdcall p_VerLanguageNameW(void)
{ __asm { jmp dword ptr [pfn_VerLanguageNameW] } }

__declspec(naked) void __stdcall p_VerQueryValueA(void)
{ __asm { jmp dword ptr [pfn_VerQueryValueA] } }

__declspec(naked) void __stdcall p_VerQueryValueW(void)
{ __asm { jmp dword ptr [pfn_VerQueryValueW] } }

// --- Gercek DLL'i yukle ve fonksiyon adreslerini al ---

static BOOL load_real_version(void)
{
    char sysDir[MAX_PATH];
    char realPath[MAX_PATH];

    GetSystemDirectoryA(sysDir, MAX_PATH);
    wsprintfA(realPath, "%s\\version.dll", sysDir);

    g_realVersion = LoadLibraryA(realPath);
    if (!g_realVersion) return FALSE;

    pfn_GetFileVersionInfoA        = GetProcAddress(g_realVersion, "GetFileVersionInfoA");
    pfn_GetFileVersionInfoByHandle = GetProcAddress(g_realVersion, "GetFileVersionInfoByHandle");
    pfn_GetFileVersionInfoExA      = GetProcAddress(g_realVersion, "GetFileVersionInfoExA");
    pfn_GetFileVersionInfoExW      = GetProcAddress(g_realVersion, "GetFileVersionInfoExW");
    pfn_GetFileVersionInfoSizeA    = GetProcAddress(g_realVersion, "GetFileVersionInfoSizeA");
    pfn_GetFileVersionInfoSizeExA  = GetProcAddress(g_realVersion, "GetFileVersionInfoSizeExA");
    pfn_GetFileVersionInfoSizeExW  = GetProcAddress(g_realVersion, "GetFileVersionInfoSizeExW");
    pfn_GetFileVersionInfoSizeW    = GetProcAddress(g_realVersion, "GetFileVersionInfoSizeW");
    pfn_GetFileVersionInfoW        = GetProcAddress(g_realVersion, "GetFileVersionInfoW");
    pfn_VerFindFileA               = GetProcAddress(g_realVersion, "VerFindFileA");
    pfn_VerFindFileW               = GetProcAddress(g_realVersion, "VerFindFileW");
    pfn_VerInstallFileA            = GetProcAddress(g_realVersion, "VerInstallFileA");
    pfn_VerInstallFileW            = GetProcAddress(g_realVersion, "VerInstallFileW");
    pfn_VerLanguageNameA           = GetProcAddress(g_realVersion, "VerLanguageNameA");
    pfn_VerLanguageNameW           = GetProcAddress(g_realVersion, "VerLanguageNameW");
    pfn_VerQueryValueA             = GetProcAddress(g_realVersion, "VerQueryValueA");
    pfn_VerQueryValueW             = GetProcAddress(g_realVersion, "VerQueryValueW");

    return TRUE;
}

// --- payload.dll'i ayni dizinden yukle ---

static void load_payload(void)
{
    char myPath[MAX_PATH];
    char payloadPath[MAX_PATH];

    GetModuleFileNameA(NULL, myPath, MAX_PATH);
    char *lastSlash = strrchr(myPath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        wsprintfA(payloadPath, "%s\\payload.dll", myPath);
    } else {
        wsprintfA(payloadPath, "payload.dll");
    }

    g_payload = LoadLibraryA(payloadPath);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (!load_real_version())
            return FALSE;

        load_payload();
        break;

    case DLL_PROCESS_DETACH:
        if (g_payload)
            FreeLibrary(g_payload);
        if (g_realVersion)
            FreeLibrary(g_realVersion);
        break;
    }
    return TRUE;
}
