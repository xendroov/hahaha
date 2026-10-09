// Payload DLL — Ana giris noktasi

#include "payload.h"

static HMODULE g_self = NULL;
static volatile BOOL g_initialized = FALSE;

static BOOL is_target_process(void)
{
    char exeName[MAX_PATH];
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    _strlwr(exeName);
    return (strstr(exeName, "knightonline") != NULL);
}

static void get_log_path(char *out, DWORD size)
{
    // Oncelik: oyun dizini, sonra TEMP, sonra Desktop
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    char *lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        snprintf(out, size, "%s\\ko_payload.log", exePath);
        // Yazilabilir mi test et
        FILE *test = fopen(out, "a");
        if (test) { fclose(test); return; }
    }

    // TEMP dizini
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    snprintf(out, size, "%sko_payload.log", temp);
}

static void startup(void)
{
    char logPath[MAX_PATH];
    get_log_path(logPath, MAX_PATH);
    log_init(logPath);
    log_write("INIT", "Payload yuklendi, base=0x%p", g_self);
    log_write("INIT", "Log dosyasi: %s", logPath);

    if (syscall_init())
        log_write("INIT", "Syscall table hazir");
    else
        log_write("INIT", "Syscall table KISMI");

    int morphed = antisig_morph_prologues(g_self);
    log_write("INIT", "Prologue morph: %s", morphed ? "OK" : "degisiklik yok");

    xmon_start();

    log_write("INIT", "Hooklar 15 sn sonra kurulacak (oyun baslasin)...");
    Sleep(15000);

    BYTE *sndCheck = (BYTE *)KO_SND_FNC;
    BYTE *rcvCheck = (BYTE *)KO_RECV_FNC;
    log_write("INIT", "Send @ 0x%08X ilk 4 byte: %02X %02X %02X %02X",
              KO_SND_FNC, sndCheck[0], sndCheck[1], sndCheck[2], sndCheck[3]);
    log_write("INIT", "Recv @ 0x%08X ilk 4 byte: %02X %02X %02X %02X",
              KO_RECV_FNC, rcvCheck[0], rcvCheck[1], rcvCheck[2], rcvCheck[3]);

    if (pcap_start())
        log_write("INIT", "Packet capture aktif");
    else
        log_write("INIT", "Packet capture BASARISIZ");

    gstate_start();

    log_write("INIT", "=== Tum moduller yuklendi ===");
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

        // DLL'i bellekte tut
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
