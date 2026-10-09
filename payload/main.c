// Payload — Ana giris noktasi
// d3d9.dll proxy icinden cagirilir (ayri DLL degil)

#include "payload.h"

static HMODULE g_self = NULL;
static volatile BOOL g_initialized = FALSE;

static void get_log_path(char *out, DWORD size)
{
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    char *lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        snprintf(out, size, "%s\\ko_payload.log", exePath);
        FILE *test = fopen(out, "a");
        if (test) { fclose(test); return; }
    }

    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    snprintf(out, size, "%sko_payload.log", temp);
}

static DWORD WINAPI startup_thread(LPVOID param)
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

    log_write("INIT", "Hooklar 20 sn sonra kurulacak...");
    Sleep(20000);

    BYTE *sndCheck = (BYTE *)KO_SND_FNC;
    BYTE *rcvCheck = (BYTE *)KO_RECV_FNC;
    log_write("INIT", "Send @ 0x%08X: %02X %02X %02X %02X",
              KO_SND_FNC, sndCheck[0], sndCheck[1], sndCheck[2], sndCheck[3]);
    log_write("INIT", "Recv @ 0x%08X: %02X %02X %02X %02X",
              KO_RECV_FNC, rcvCheck[0], rcvCheck[1], rcvCheck[2], rcvCheck[3]);

    if (pcap_start())
        log_write("INIT", "Packet capture aktif");
    else
        log_write("INIT", "Packet capture BASARISIZ");

    gstate_start();

    log_write("INIT", "=== Tum moduller yuklendi ===");
    return 0;
}

void payload_startup(HMODULE selfModule)
{
    if (g_initialized) return;
    g_initialized = TRUE;
    g_self = selfModule;
    CreateThread(NULL, 0, startup_thread, NULL, 0, NULL);
}

void payload_shutdown(void)
{
    if (!g_initialized) return;
    log_write("INIT", "Payload kapaniyor...");
    gstate_stop();
    pcap_stop();
    xmon_stop();
    log_write("INIT", "Temiz cikis");
    log_close();
}
