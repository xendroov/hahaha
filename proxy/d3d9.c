// d3d9.dll proxy — tek dosya, payload gomulu
//
// Tum payload kodu bu DLL icinde derlenir. Ayri payload.dll YOK.
// XIGNCODE modul taramasinda sadece d3d9.dll gorur (DirectX DLL'i olarak normal).
//
// Akis:
//   1. OS oyunu baslatir → d3d9.dll (bizimki) uygulama dizininden yuklenir
//   2. DllMain: gercek d3d9.dll System32'den yuklenir, export'lar iletilir
//   3. DllMain: payload_startup() cagirilir → arka plan thread baslar
//   4. XIGNCODE baslar → modul listesinde sadece d3d9.dll (supheli degil)

#include <windows.h>
#include <string.h>
#include "../payload/payload.h"

static HMODULE g_realD3D9 = NULL;

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

static BOOL is_target_process(void)
{
    char exeName[MAX_PATH];
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    _strlwr(exeName);
    char t[16];
    t[0]='k'; t[1]='n'; t[2]='i'; t[3]='g'; t[4]='h'; t[5]='t';
    t[6]='o'; t[7]='n'; t[8]='l'; t[9]='i'; t[10]='n'; t[11]='e';
    t[12]='\0';
    return (strstr(exeName, t) != NULL);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (!load_real_d3d9())
            return FALSE;

        if (is_target_process())
            payload_startup(hModule);
        break;

    case DLL_PROCESS_DETACH:
        payload_shutdown();
        if (g_realD3D9)
            FreeLibrary(g_realD3D9);
        break;
    }
    return TRUE;
}
