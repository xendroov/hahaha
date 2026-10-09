// d3d9.dll proxy — DirectX 9 DLL arama sirasi ile payload yukle
//
// KnightOnLine bir DirectX 9 oyunu — d3d9.dll KESINLIKLE kullaniliyor.
// version.dll calismadi cunku Windows 10 API set ile cozuyor (aramaya girmiyor).
// d3d9.dll KnownDLL degil, API set degil — uygulama dizini ONCE aranir.
//
// Oyun dizinine d3d9.dll (bu proxy) + payload.dll koyuyoruz.
// OS oyunu baslatinca bizim d3d9.dll'i yukler, biz de:
//   a) Gercek d3d9.dll'i System32'den yukleriz
//   b) payload.dll'i yukleriz
//
// XIGNCODE henuz aktif degil — payload guvende yuklenir.

#include <windows.h>

static HMODULE g_realD3D9   = NULL;
static HMODULE g_payload    = NULL;

// Gercek d3d9.dll fonksiyon isaretcileri
static FARPROC pfn_Direct3DCreate9;
static FARPROC pfn_Direct3DCreate9Ex;
static FARPROC pfn_Direct3DCreate9On12;
static FARPROC pfn_Direct3DCreate9On12Ex;
static FARPROC pfn_Direct3DShaderValidatorCreate9;
static FARPROC pfn_D3DPERF_BeginEvent;
static FARPROC pfn_D3DPERF_EndEvent;
static FARPROC pfn_D3DPERF_GetStatus;
static FARPROC pfn_D3DPERF_QueryRepeatFrame;
static FARPROC pfn_D3DPERF_SetMarker;
static FARPROC pfn_D3DPERF_SetOptions;
static FARPROC pfn_D3DPERF_SetRegion;
static FARPROC pfn_DebugSetLevel;
static FARPROC pfn_DebugSetMute;
static FARPROC pfn_PSGPError;
static FARPROC pfn_PSGPSampleTexture;
static FARPROC pfn_Direct3D9ForceHybridEnumeration;

// --- Naked forwarder stub'lari (MSVC x86) ---

__declspec(naked) void __stdcall p_Direct3DCreate9(void)
{ __asm { jmp dword ptr [pfn_Direct3DCreate9] } }

__declspec(naked) void __stdcall p_Direct3DCreate9Ex(void)
{ __asm { jmp dword ptr [pfn_Direct3DCreate9Ex] } }

__declspec(naked) void __stdcall p_Direct3DCreate9On12(void)
{ __asm { jmp dword ptr [pfn_Direct3DCreate9On12] } }

__declspec(naked) void __stdcall p_Direct3DCreate9On12Ex(void)
{ __asm { jmp dword ptr [pfn_Direct3DCreate9On12Ex] } }

__declspec(naked) void __stdcall p_Direct3DShaderValidatorCreate9(void)
{ __asm { jmp dword ptr [pfn_Direct3DShaderValidatorCreate9] } }

__declspec(naked) void __stdcall p_D3DPERF_BeginEvent(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_BeginEvent] } }

__declspec(naked) void __stdcall p_D3DPERF_EndEvent(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_EndEvent] } }

__declspec(naked) void __stdcall p_D3DPERF_GetStatus(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_GetStatus] } }

__declspec(naked) void __stdcall p_D3DPERF_QueryRepeatFrame(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_QueryRepeatFrame] } }

__declspec(naked) void __stdcall p_D3DPERF_SetMarker(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_SetMarker] } }

__declspec(naked) void __stdcall p_D3DPERF_SetOptions(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_SetOptions] } }

__declspec(naked) void __stdcall p_D3DPERF_SetRegion(void)
{ __asm { jmp dword ptr [pfn_D3DPERF_SetRegion] } }

__declspec(naked) void __stdcall p_DebugSetLevel(void)
{ __asm { jmp dword ptr [pfn_DebugSetLevel] } }

__declspec(naked) void __stdcall p_DebugSetMute(void)
{ __asm { jmp dword ptr [pfn_DebugSetMute] } }

__declspec(naked) void __stdcall p_PSGPError(void)
{ __asm { jmp dword ptr [pfn_PSGPError] } }

__declspec(naked) void __stdcall p_PSGPSampleTexture(void)
{ __asm { jmp dword ptr [pfn_PSGPSampleTexture] } }

__declspec(naked) void __stdcall p_Direct3D9ForceHybridEnumeration(void)
{ __asm { jmp dword ptr [pfn_Direct3D9ForceHybridEnumeration] } }

// --- Gercek d3d9.dll'i System32'den yukle ---

static BOOL load_real_d3d9(void)
{
    char sysDir[MAX_PATH];
    char realPath[MAX_PATH];

    GetSystemDirectoryA(sysDir, MAX_PATH);
    wsprintfA(realPath, "%s\\d3d9.dll", sysDir);

    g_realD3D9 = LoadLibraryA(realPath);
    if (!g_realD3D9) return FALSE;

    pfn_Direct3DCreate9                  = GetProcAddress(g_realD3D9, "Direct3DCreate9");
    pfn_Direct3DCreate9Ex                = GetProcAddress(g_realD3D9, "Direct3DCreate9Ex");
    pfn_Direct3DCreate9On12              = GetProcAddress(g_realD3D9, "Direct3DCreate9On12");
    pfn_Direct3DCreate9On12Ex            = GetProcAddress(g_realD3D9, "Direct3DCreate9On12Ex");
    pfn_Direct3DShaderValidatorCreate9   = GetProcAddress(g_realD3D9, "Direct3DShaderValidatorCreate9");
    pfn_D3DPERF_BeginEvent               = GetProcAddress(g_realD3D9, "D3DPERF_BeginEvent");
    pfn_D3DPERF_EndEvent                 = GetProcAddress(g_realD3D9, "D3DPERF_EndEvent");
    pfn_D3DPERF_GetStatus                = GetProcAddress(g_realD3D9, "D3DPERF_GetStatus");
    pfn_D3DPERF_QueryRepeatFrame         = GetProcAddress(g_realD3D9, "D3DPERF_QueryRepeatFrame");
    pfn_D3DPERF_SetMarker                = GetProcAddress(g_realD3D9, "D3DPERF_SetMarker");
    pfn_D3DPERF_SetOptions               = GetProcAddress(g_realD3D9, "D3DPERF_SetOptions");
    pfn_D3DPERF_SetRegion                = GetProcAddress(g_realD3D9, "D3DPERF_SetRegion");
    pfn_DebugSetLevel                    = GetProcAddress(g_realD3D9, "DebugSetLevel");
    pfn_DebugSetMute                     = GetProcAddress(g_realD3D9, "DebugSetMute");
    pfn_PSGPError                        = GetProcAddress(g_realD3D9, "PSGPError");
    pfn_PSGPSampleTexture                = GetProcAddress(g_realD3D9, "PSGPSampleTexture");
    pfn_Direct3D9ForceHybridEnumeration  = GetProcAddress(g_realD3D9, "Direct3D9ForceHybridEnumeration");

    return (pfn_Direct3DCreate9 != NULL);
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

        if (!load_real_d3d9())
            return FALSE;

        load_payload();
        break;

    case DLL_PROCESS_DETACH:
        if (g_payload)
            FreeLibrary(g_payload);
        if (g_realD3D9)
            FreeLibrary(g_realD3D9);
        break;
    }
    return TRUE;
}
