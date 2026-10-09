// Payload DLL — Ana giris noktasi
//
// Injection sonrasi sira:
//   1. Anti-Signature (header sil + prologue morph)
//   2. Syscall table olustur (ntdll'e dokunmadan kernel erisimi)
//   3. Log sistemi baslat
//   4. XIGNCODE monitor baslat
//   5. Packet capture hook kur
//   6. Game state reader baslat

#include "payload.h"

static HMODULE g_self = NULL;
static volatile BOOL g_initialized = FALSE;

static BOOL is_target_process(void)
{
    char exeName[MAX_PATH];
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    return (strstr(exeName, "KnightOnLine") != NULL ||
            strstr(exeName, "knightonline") != NULL);
}

static void startup(void)
{
    antisig_wipe_header(g_self);
    antisig_morph_prologues(g_self);

    syscall_init();

    log_init("C:\\ko_payload.log");
    log_write("INIT", "Payload yuklendi, base=0x%p", g_self);

    xmon_start();

    if (pcap_start())
        log_write("INIT", "Packet capture aktif");
    else
        log_write("INIT", "Packet capture BASARISIZ");

    gstate_start();

    log_write("INIT", "Tum moduller yuklendi");
}

static void payload_shutdown(void)
{
    if (!g_initialized) return;

    log_write("INIT", "Payload kapaniyor...");

    gstate_stop();
    pcap_stop();
    xmon_stop();

    log_write("INIT", "Temiz cikis");
    log_close();
}

// SetWindowsHookEx icin export — injector bu fonksiyonu cagirir
__declspec(dllexport) LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_self = hModule;
        DisableThreadLibraryCalls(hModule);

        if (!is_target_process())
            break;

        if (g_initialized)
            break;
        g_initialized = TRUE;

        // DLL'i bellekte tut (hook kaldirilsa bile)
        {
            char selfPath[MAX_PATH];
            GetModuleFileNameA(hModule, selfPath, MAX_PATH);
            LoadLibraryA(selfPath);
        }

        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startup, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        payload_shutdown();
        break;
    }
    return TRUE;
}
