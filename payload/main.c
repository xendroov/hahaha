// Payload DLL — Ana giris noktasi
//
// Injection sonrasi sira:
//   1. Anti-Signature (header sil + prologue morph)
//   2. Syscall table olustur (ntdll'e dokunmadan kernel erisimi)
//   3. Log sistemi baslat
//   4. XIGNCODE monitor baslat
//   5. Packet capture hook kur
//   6. Game state reader baslat
//
// DLL_PROCESS_DETACH'te temiz cikis.

#include "payload.h"

static HMODULE g_self = NULL;

static void startup(void)
{
    // 1. Anti-signature: PE header'i sil, imza kir
    antisig_wipe_header(g_self);
    antisig_morph_prologues(g_self);

    // 2. Direct syscall table
    syscall_init();

    // 3. Log
    log_init("C:\\ko_payload.log");
    log_write("INIT", "Payload yuklendi, base=0x%p", g_self);

    // 4. XIGNCODE monitor
    xmon_start();

    // 5. Packet capture
    if (pcap_start())
        log_write("INIT", "Packet capture aktif");
    else
        log_write("INIT", "Packet capture BASARISIZ — adres gecersiz olabilir");

    // 6. Game state reader
    gstate_start();

    log_write("INIT", "Tum moduller yuklendi");
}

static void payload_shutdown(void)
{
    log_write("INIT", "Payload kapaniyor...");

    gstate_stop();
    pcap_stop();
    xmon_stop();

    log_write("INIT", "Temiz cikis");
    log_close();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_self = hModule;
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startup, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        payload_shutdown();
        break;
    }
    return TRUE;
}
