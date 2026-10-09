// XIGNCODE Monitor — XIGNCODE'un ne yaptığını logla
//
// ntdll'e hook koymadan, periyodik olarak:
//   1. ntdll fonksiyonlarının integrity'sini kontrol et
//   2. XIGNCODE modüllerinin durumunu logla
//   3. Thread listesini tara (yeni XIGNCODE thread'leri?)
//   4. NtProtectVirtualMemory çağrılarını izle (okuma/yazma koruması değişiklikleri)

#include "payload.h"
#include <tlhelp32.h>

static volatile BOOL g_xmon_running = FALSE;
static HANDLE g_xmon_thread = NULL;

// ntdll fonksiyonlarının ilk byte'larını logla (hook kontrolü)
static void check_ntdll(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    const char *targets[] = {
        "NtProtectVirtualMemory", "NtQueryVirtualMemory",
        "NtReadVirtualMemory",    "NtWriteVirtualMemory",
        "NtOpenProcess",          "NtQuerySystemInformation",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "NtGetContextThread",     "NtCreateThreadEx",
        "NtMapViewOfSection",     "NtClose",
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        BYTE *fn = (BYTE *)GetProcAddress(ntdll, targets[i]);
        if (!fn) continue;

        char hex[64] = {0};
        int pos = 0;
        for (int j = 0; j < 8; j++)
            pos += sprintf(hex + pos, "%02X ", fn[j]);

        const char *status = "CLEAN";
        if (fn[0] == 0xE9) status = "HOOKED(JMP)";
        else if (fn[0] == 0xCC) status = "HOOKED(INT3)";
        else if (fn[0] == 0x68) status = "HOOKED(PUSH)";
        else if (fn[0] != 0xB8) status = "UNKNOWN";

        log_write("XMON", "  %s @ %p: %s [%s]", targets[i], fn, hex, status);
    }
}

// XIGNCODE modüllerini ve boyutlarını logla
static void check_xign_modules(void)
{
    const char *modules[] = {
        "x3.xem", "xcorona.xem", "xcorona_x64.xem",
        "xmag.xem", "xnina.xem", "xxd-0.xem", "xm.exe",
        NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me = { .dwSize = sizeof(me) };
    if (Module32First(snap, &me)) {
        do {
            for (int i = 0; modules[i]; i++) {
                if (_stricmp(me.szModule, modules[i]) == 0) {
                    log_write("XMON", "  [XIGN] %s base=%p size=0x%X",
                              me.szModule, me.modBaseAddr, me.modBaseSize);
                }
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

// Thread listesi — XIGNCODE'un oluşturduğu thread'leri bul
static void check_threads(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD pid = GetCurrentProcessId();
    int count = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                count++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    log_write("XMON", "  Thread sayisi: %d", count);
}

// Bellekteki şüpheli bölgeleri tara
static void check_memory(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = NULL;
    int rwxCount = 0;
    int privExecCount = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.Type == MEM_PRIVATE)
                rwxCount++;
            if ((mbi.Protect & PAGE_EXECUTE) && mbi.Type == MEM_PRIVATE)
                privExecCount++;
        }
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr >= 0x7FFE0000) break;
    }

    log_write("XMON", "  RWX private bolge: %d, Exec private: %d",
              rwxCount, privExecCount);
}

// Ana monitor döngüsü
static DWORD WINAPI xmon_thread(LPVOID param)
{
    int cycle = 0;

    while (g_xmon_running) {
        cycle++;
        log_write("XMON", "=== Scan cycle %d ===", cycle);

        check_ntdll();
        check_xign_modules();
        check_threads();
        check_memory();

        // 5 saniyede bir tara
        for (int i = 0; i < 50 && g_xmon_running; i++)
            Sleep(100);
    }

    log_write("XMON", "Monitor durduruldu");
    return 0;
}

void xmon_start(void)
{
    if (g_xmon_running) return;
    g_xmon_running = TRUE;
    g_xmon_thread = CreateThread(NULL, 0, xmon_thread, NULL, 0, NULL);
    log_write("XMON", "XIGNCODE monitor baslatildi");
}

void xmon_stop(void)
{
    g_xmon_running = FALSE;
    if (g_xmon_thread) {
        WaitForSingleObject(g_xmon_thread, 3000);
        CloseHandle(g_xmon_thread);
        g_xmon_thread = NULL;
    }
}
