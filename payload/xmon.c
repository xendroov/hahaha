#include "payload.h"
#include <string.h>
#include <tlhelp32.h>

/*
 * XIGNCODE3 Monitor & Bypass
 *
 * xigncode.log analizinden (3000 kayit):
 *   - CheckRemoteDebuggerPresent: 91 cagri, 3 dalga (her 4 kayitta 3'u bu)
 *   - NTDLL.DLL integrity check: kayit #607
 *   - server.ini okuma: kayit #609, #1866
 *   - Toplu tarama: ~493 kayit (modul/bellek)
 *   - Rutin rapor: 1478 kayit (0B 10 tipi)
 *
 * Bypass:
 *   1) CheckRemoteDebuggerPresent hook -> her zaman FALSE
 *   2) ntdll'e dokunmuyoruz (direct syscall ile bypass)
 *   3) PEB.BeingDebugged = 0
 *   4) NtGlobalFlag temizle
 *   5) XIGNCODE modul aktivitesi izleme
 */

static BYTE g_crdbp_orig[8];
static BYTE *g_crdbp_addr = NULL;
static volatile BOOL g_xmon_running = FALSE;
static HANDLE g_xmon_thread = NULL;

static BOOL WINAPI fake_crdbp(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
    (void)hProcess;
    if (pbDebuggerPresent)
        *pbDebuggerPresent = FALSE;
    return TRUE;
}

static BOOL patch_bytes(BYTE *target, BYTE *newBytes, int len)
{
    DWORD old;
    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    memcpy(target, newBytes, len);
    VirtualProtect(target, len, old, &old);
    return TRUE;
}

static BOOL hook_crdbp(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return FALSE;

    g_crdbp_addr = (BYTE *)GetProcAddress(k32, "CheckRemoteDebuggerPresent");
    if (!g_crdbp_addr) return FALSE;

    DWORD old;
    if (!VirtualProtect(g_crdbp_addr, 8, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;

    memcpy(g_crdbp_orig, g_crdbp_addr, 8);

    g_crdbp_addr[0] = 0xE9;
    *(DWORD *)(g_crdbp_addr + 1) =
        (DWORD)((BYTE *)fake_crdbp - g_crdbp_addr - 5);

    VirtualProtect(g_crdbp_addr, 8, old, &old);
    log_write("X", "HOOK CRDBP @0x%p", g_crdbp_addr);
    return TRUE;
}

static void unhook_crdbp(void)
{
    if (!g_crdbp_addr) return;
    patch_bytes(g_crdbp_addr, g_crdbp_orig, 8);
    g_crdbp_addr = NULL;
}

static void patch_peb_flags(void)
{
    DWORD peb;
    __asm {
        mov eax, dword ptr fs:[0x30]
        mov peb, eax
    }

    *(BYTE *)(peb + 0x02) = 0;

    DWORD ntGlobalFlag = *(DWORD *)(peb + 0x68);
    if (ntGlobalFlag & 0x70) {
        *(DWORD *)(peb + 0x68) = ntGlobalFlag & ~0x70;
        log_write("X", "PEB NtGlobalFlag 0x%X -> 0x%X",
                  ntGlobalFlag, *(DWORD *)(peb + 0x68));
    }

    DWORD heapBase = *(DWORD *)(peb + 0x18);
    if (heapBase) {
        DWORD flags     = *(DWORD *)(heapBase + 0x0C);
        DWORD forceFlags = *(DWORD *)(heapBase + 0x10);
        if (flags != 0x02 || forceFlags != 0x00) {
            *(DWORD *)(heapBase + 0x0C) = 0x02;
            *(DWORD *)(heapBase + 0x10) = 0x00;
            log_write("X", "PEB Heap flags fixed");
        }
    }

    log_write("X", "PEB BeingDebugged=0");
}

static void check_ntdll_hooks(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    const char *targets[] = {
        "NtProtectVirtualMemory",
        "NtQueryVirtualMemory",
        "NtReadVirtualMemory",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "NtClose",
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        BYTE *fn = (BYTE *)GetProcAddress(ntdll, targets[i]);
        if (!fn) continue;
        if (fn[0] == 0xE9 || fn[0] == 0xCC || fn[0] == 0x68) {
            log_write("X", "NTDLL HOOK %s @%p [%02X %02X %02X %02X %02X]",
                      targets[i], fn, fn[0], fn[1], fn[2], fn[3], fn[4]);
        }
    }
}

static void scan_xign_modules(void)
{
    const char *xm[] = {
        "x3.xem", "xcorona.xem", "xcorona_x64.xem",
        "xmag.xem", "xnina.xem", "xxd-0.xem", NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                                           GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    if (Module32First(snap, &me)) {
        do {
            for (int i = 0; xm[i]; i++) {
                if (_stricmp(me.szModule, xm[i]) == 0) {
                    log_write("X", "XIGN %s @%p sz=0x%X",
                              me.szModule, me.modBaseAddr, me.modBaseSize);
                }
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

static DWORD WINAPI xmon_thread(LPVOID param)
{
    (void)param;

    scan_xign_modules();
    check_ntdll_hooks();

    DWORD cycle = 0;
    while (g_xmon_running) {
        cycle++;

        if (cycle % 6 == 0)
            scan_xign_modules();

        if (cycle % 10 == 0)
            check_ntdll_hooks();

        if (cycle % 3 == 0) {
            DWORD peb;
            __asm {
                mov eax, dword ptr fs:[0x30]
                mov peb, eax
            }
            if (*(BYTE *)(peb + 0x02) != 0) {
                *(BYTE *)(peb + 0x02) = 0;
                log_write("X", "PEB re-patched cycle %u", cycle);
            }
        }

        for (int i = 0; i < 100 && g_xmon_running; i++)
            Sleep(100);
    }
    return 0;
}

void xmon_start(void)
{
    if (g_xmon_running) return;

    hook_crdbp();
    patch_peb_flags();

    g_xmon_running = TRUE;
    g_xmon_thread = CreateThread(NULL, 0, xmon_thread, NULL, 0, NULL);
    log_write("X", "xmon started");
}

void xmon_stop(void)
{
    g_xmon_running = FALSE;

    unhook_crdbp();

    if (g_xmon_thread) {
        WaitForSingleObject(g_xmon_thread, 5000);
        CloseHandle(g_xmon_thread);
        g_xmon_thread = NULL;
    }
    log_write("X", "xmon stopped");
}
