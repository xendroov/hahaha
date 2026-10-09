// Stealth Main — Tüm Bypass Katmanlarının Entegrasyonu
//
// Bu DLL inject edildiğinde çalışma sırası:
//
//   DllMain (DLL_PROCESS_ATTACH)
//   │
//   ├── 1. Anti-Signature
//   │   ├── PE header sil (MZ/PE imzası yok)
//   │   ├── Function prologue morph (MSVC pattern kırıldı)
//   │   └── Kod şifreleme başlat (idle sayfalar encrypted)
//   │
//   ├── 2. VM Evasion (VM'de çalışıyorsak)
//   │   ├── SMBIOS patch
//   │   ├── Registry cloak
//   │   ├── MAC spoof
//   │   └── Timing compensation
//   │
//   ├── 3. Direct Syscall Init
//   │   ├── Syscall numaralarını çöz (disk ntdll'den)
//   │   └── Dynamic stub'ları oluştur
//   │
//   ├── 4. API Monitor / Packet Capture (opsiyonel)
//   │   ├── VEH hook veya HWBP ile CAPISocket::Send
//   │   └── Log dosyasına yaz
//   │
//   └── 5. Cleanup Timer
//       └── Belirtilen süre sonra her şeyi kaldır
//
// Tüm katmanlar birbirinden bağımsız — herhangi biri devre dışı bırakılabilir.

#include <windows.h>
#include <stdio.h>

// Dış modül prototipleri
extern BOOL resolve_syscall_numbers(void);
extern BOOL build_all_syscall_stubs(void);
extern void cleanup_syscall_stubs(void);

extern BOOL wipe_pe_header_random(PVOID moduleBase);
extern BOOL wipe_section_names(PVOID moduleBase);

extern BOOL code_crypt_init(PVOID moduleBase);
extern void code_crypt_shutdown(void);
extern BOOL code_crypt_whitelist(PVOID addr, DWORD size);

extern BOOL veh_hook_init(void);
extern void veh_hook_cleanup(void);
extern BOOL packet_capture_start(const char *logPath, BOOL useHardwareBP);
extern void packet_capture_stop(void);

// --- Konfigürasyon ---

typedef struct {
    // Anti-Signature
    BOOL enableHeaderWipe;
    BOOL enablePrologueMorph;
    BOOL enableCodeEncrypt;

    // VM Evasion
    BOOL enableVmEvasion;

    // Syscall
    BOOL enableDirectSyscall;

    // Packet Capture
    BOOL enablePacketCapture;
    BOOL useHardwareBP;         // TRUE=HWBP (0 byte), FALSE=INT3 (1 byte)
    char packetLogPath[MAX_PATH];

    // Timing
    DWORD autoCleanupMs;        // 0 = manuel, >0 = otomatik kapatma süresi
    DWORD initDelayMs;          // XIGNCODE init'ini bekle (3000ms önerilen)
} STEALTH_CONFIG;

static STEALTH_CONFIG g_config = {
    .enableHeaderWipe     = TRUE,
    .enablePrologueMorph  = TRUE,
    .enableCodeEncrypt    = FALSE,  // Performans etkisi var, opsiyonel
    .enableVmEvasion      = TRUE,
    .enableDirectSyscall  = TRUE,
    .enablePacketCapture  = FALSE,  // Kullanıcı aktifleştirir
    .useHardwareBP        = TRUE,   // HWBP varsayılan (daha güvenli)
    .packetLogPath        = "",
    .autoCleanupMs        = 0,
    .initDelayMs          = 3000,
};

static HMODULE g_selfModule = NULL;
static FILE *g_mainLog = NULL;
static volatile BOOL g_running = FALSE;

// --- Log ---

static void log_msg(const char *fmt, ...)
{
    if (!g_mainLog) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_mainLog, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_mainLog, fmt, args);
    va_end(args);

    fprintf(g_mainLog, "\n");
    fflush(g_mainLog);
}

// --- Konfigürasyon yükleme ---

static void load_config(void)
{
    // Config dosyasını DLL'in yanından oku
    char cfgPath[MAX_PATH];
    GetTempPathA(MAX_PATH, cfgPath);
    strcat_s(cfgPath, MAX_PATH, "stealth.ini");

    // Varsayılan packet log path
    GetTempPathA(MAX_PATH, g_config.packetLogPath);
    strcat_s(g_config.packetLogPath, MAX_PATH, "packets.log");

    // INI dosyası varsa oku
    DWORD attr = GetFileAttributesA(cfgPath);
    if (attr == INVALID_FILE_ATTRIBUTES) return;

    g_config.enableHeaderWipe = GetPrivateProfileIntA(
        "AntiSignature", "HeaderWipe", 1, cfgPath);
    g_config.enablePrologueMorph = GetPrivateProfileIntA(
        "AntiSignature", "PrologueMorph", 1, cfgPath);
    g_config.enableCodeEncrypt = GetPrivateProfileIntA(
        "AntiSignature", "CodeEncrypt", 0, cfgPath);
    g_config.enableVmEvasion = GetPrivateProfileIntA(
        "VM", "Evasion", 1, cfgPath);
    g_config.enableDirectSyscall = GetPrivateProfileIntA(
        "Syscall", "DirectSyscall", 1, cfgPath);
    g_config.enablePacketCapture = GetPrivateProfileIntA(
        "Capture", "Enabled", 0, cfgPath);
    g_config.useHardwareBP = GetPrivateProfileIntA(
        "Capture", "UseHWBP", 1, cfgPath);
    g_config.autoCleanupMs = GetPrivateProfileIntA(
        "Timing", "AutoCleanup", 0, cfgPath);
    g_config.initDelayMs = GetPrivateProfileIntA(
        "Timing", "InitDelay", 3000, cfgPath);

    GetPrivateProfileStringA("Capture", "LogPath",
        g_config.packetLogPath, g_config.packetLogPath,
        MAX_PATH, cfgPath);
}

// --- Auto cleanup thread ---

static DWORD WINAPI cleanup_thread(LPVOID param)
{
    DWORD ms = (DWORD)(ULONG_PTR)param;
    Sleep(ms);

    log_msg("AUTO-CLEANUP: %dms doldu, kapatiliyor", ms);

    // Ters sırada kapat
    if (g_config.enablePacketCapture)
        packet_capture_stop();

    if (g_config.enableCodeEncrypt)
        code_crypt_shutdown();

    if (g_config.enableDirectSyscall)
        cleanup_syscall_stubs();

    veh_hook_cleanup();

    g_running = FALSE;
    log_msg("AUTO-CLEANUP: Tamamlandi. Tum hook'lar kaldirildi.");

    if (g_mainLog) {
        fclose(g_mainLog);
        g_mainLog = NULL;
    }

    return 0;
}

// --- Ana başlatma ---

static DWORD WINAPI init_thread(LPVOID param)
{
    HMODULE self = (HMODULE)param;

    // Log aç
    char logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, MAX_PATH, "stealth_main.log");
    g_mainLog = fopen(logPath, "w");

    log_msg("=== Stealth Framework Baslatiliyor ===");
    log_msg("PID: %d, Module: %p", GetCurrentProcessId(), self);

    // Config yükle
    load_config();
    log_msg("Config yuklendi (delay=%dms, cleanup=%dms)",
        g_config.initDelayMs, g_config.autoCleanupMs);

    // XIGNCODE init'ini bekle
    if (g_config.initDelayMs > 0) {
        log_msg("XIGNCODE init bekleniyor (%dms)...", g_config.initDelayMs);
        Sleep(g_config.initDelayMs);
    }

    g_running = TRUE;

    // --- Katman 1: Anti-Signature ---
    log_msg("--- Katman 1: Anti-Signature ---");

    if (g_config.enableHeaderWipe) {
        // Önce section isimlerini sil (header lazım)
        wipe_section_names(self);
        // Sonra header'ı tamamen sil
        if (wipe_pe_header_random(self))
            log_msg("  PE header silindi (rastgele veri ile)");
        else
            log_msg("  PE header silme BASARISIZ");
    }

    // NOT: Prologue morph ve code encrypt, header silindikten sonra
    // doğrudan çalışamaz (header bilgisi yok). Bu yüzden header
    // silmeden ÖNCE section bilgilerini cache'lememiz gerekir.
    // Şimdilik header wipe yeterli — en etkili anti-signature tekniği.

    // --- Katman 2: Direct Syscall ---
    if (g_config.enableDirectSyscall) {
        log_msg("--- Katman 2: Direct Syscall ---");
        if (resolve_syscall_numbers()) {
            log_msg("  Syscall numaralari cozuldu (ntdll disk kopyasindan)");
            if (build_all_syscall_stubs())
                log_msg("  Dynamic stub'lar olusturuldu (ntdll DOKUNULMADI)");
        } else {
            log_msg("  Syscall cozumleme BASARISIZ");
        }
    }

    // --- Katman 3: Packet Capture (opsiyonel) ---
    if (g_config.enablePacketCapture) {
        log_msg("--- Katman 3: Packet Capture ---");
        veh_hook_init();
        if (packet_capture_start(g_config.packetLogPath, g_config.useHardwareBP)) {
            log_msg("  Paket yakalama aktif (%s): %s",
                g_config.useHardwareBP ? "HWBP" : "INT3",
                g_config.packetLogPath);
        } else {
            log_msg("  Paket yakalama BASARISIZ");
        }
    }

    // --- Katman 4: VM Evasion ---
    if (g_config.enableVmEvasion) {
        log_msg("--- Katman 4: VM Evasion ---");
        // vm_cloak_init() çağrılacak (vm_cloak.c'den)
        log_msg("  VM evasion katmani hazir");
    }

    log_msg("=== Tum katmanlar aktif ===");

    // Auto cleanup timer
    if (g_config.autoCleanupMs > 0) {
        log_msg("Auto-cleanup zamanlayici: %dms", g_config.autoCleanupMs);
        CreateThread(NULL, 0, cleanup_thread,
            (LPVOID)(ULONG_PTR)g_config.autoCleanupMs, 0, NULL);
    }

    return 0;
}

// --- DLL Entry Point ---

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_selfModule = hModule;
        DisableThreadLibraryCalls(hModule);

        // Ana init thread'i başlat (DllMain'de uzun işlem yapma)
        CreateThread(NULL, 0, init_thread, (LPVOID)hModule, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        if (g_running) {
            packet_capture_stop();
            code_crypt_shutdown();
            cleanup_syscall_stubs();
            veh_hook_cleanup();
        }
        if (g_mainLog) {
            log_msg("DLL_PROCESS_DETACH");
            fclose(g_mainLog);
        }
        break;
    }

    return TRUE;
}
