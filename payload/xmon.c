#include "payload.h"
#include <string.h>
#include <tlhelp32.h>

/*
 * XIGNCODE3 Monitor & Bypass — v2
 *
 * Tespit vektorleri (kullanici raporundan):
 *
 *   ANTI-DEBUG:
 *   1) CheckRemoteDebuggerPresent — 91 cagri, 3 dalga
 *   2) Hardware Breakpoint (DR0-DR7) — GetThreadContext ile kontrol
 *   3) PEB.BeingDebugged + NtGlobalFlag + Heap flags
 *   4) NTDLL integrity check (hook tespiti)
 *
 *   MODUL TARAMA:
 *   5) Debugger kara listesi: CE, x64dbg, OllyDbg, WinDbg, PH, PE Tools
 *   6) XIGNCODE modulleri: x3.xem, xcorona.xem, xmag.xem, xnina.xem
 *   7) VM/Sandbox: VBox, VMware, Sandboxie DLL'leri
 *
 *   GRAFIK:
 *   8) DXGI + D3D11 SwapChain vtable hook tespiti
 *      (d3d9 kontrolu YOK — proxy guvenli)
 *
 *   FORENSIC:
 *   9) Prefetch scanner — C:\Windows\Prefetch\*.pf
 *  10) USN Journal — NTFS degisim kaydi
 *  11) Icon hash — PE resource karsilastirmasi
 *  12) AHK & macro tespiti
 *
 * Bypass katmanlari:
 *   A) CRDBP hook → her zaman FALSE
 *   B) GetThreadContext hook → DR0-DR7 sifirla
 *   C) PEB/Heap/NtGlobalFlag patch
 *   D) ntdll'e dokunmuyoruz (direct syscall)
 *   E) Periyodik DR register temizligi
 *   F) XIGNCODE modul/hook izleme
 */

// --- Anti-Debug: CRDBP ---

static BYTE g_crdbp_orig[8];
static BYTE *g_crdbp_addr = NULL;

static BOOL WINAPI fake_crdbp(HANDLE hProcess, PBOOL pbDebuggerPresent)
{
    (void)hProcess;
    if (pbDebuggerPresent)
        *pbDebuggerPresent = FALSE;
    return TRUE;
}

// --- Anti-Debug: GetThreadContext hook (DR register gizleme) ---

static BYTE g_gtc_orig[8];
static BYTE *g_gtc_addr = NULL;

typedef BOOL (WINAPI *fnGetThreadContext)(HANDLE, LPCONTEXT);
static fnGetThreadContext g_real_gtc = NULL;

static BOOL WINAPI fake_gtc(HANDLE hThread, LPCONTEXT lpContext)
{
    BOOL ret;

    if (g_real_gtc)
        ret = g_real_gtc(hThread, lpContext);
    else
        ret = FALSE;

    if (ret && lpContext) {
        if (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
            lpContext->Dr0 = 0;
            lpContext->Dr1 = 0;
            lpContext->Dr2 = 0;
            lpContext->Dr3 = 0;
            lpContext->Dr6 = 0;
            lpContext->Dr7 = 0;
        }
    }
    return ret;
}

// --- Genel hook altyapisi ---

static volatile BOOL g_xmon_running = FALSE;
static HANDLE g_xmon_thread = NULL;

static BOOL patch_bytes(BYTE *target, BYTE *newBytes, int len)
{
    DWORD old;
    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    memcpy(target, newBytes, len);
    VirtualProtect(target, len, old, &old);
    return TRUE;
}

static BOOL install_jmp_hook(BYTE *target, BYTE *detour, BYTE *backup,
                             int saveLen)
{
    DWORD old;
    if (!VirtualProtect(target, saveLen, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;

    memcpy(backup, target, saveLen);

    target[0] = 0xE9;
    *(DWORD *)(target + 1) = (DWORD)(detour - target - 5);

    for (int i = 5; i < saveLen; i++)
        target[i] = 0x90;

    VirtualProtect(target, saveLen, old, &old);
    return TRUE;
}

// --- Hook kurulumlari ---

static BOOL hook_crdbp(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return FALSE;

    g_crdbp_addr = (BYTE *)GetProcAddress(k32, "CheckRemoteDebuggerPresent");
    if (!g_crdbp_addr) return FALSE;

    if (!install_jmp_hook(g_crdbp_addr, (BYTE *)fake_crdbp, g_crdbp_orig, 8))
        return FALSE;

    log_write("X", "HOOK CRDBP @0x%p", g_crdbp_addr);
    return TRUE;
}

static BOOL hook_getthreadcontext(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return FALSE;

    g_gtc_addr = (BYTE *)GetProcAddress(k32, "GetThreadContext");
    if (!g_gtc_addr) return FALSE;

    BYTE *tramp = (BYTE *)VirtualAlloc(NULL, 32,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!tramp) return FALSE;

    memcpy(tramp, g_gtc_addr, 8);
    tramp[8] = 0xE9;
    *(DWORD *)(tramp + 9) = (DWORD)(g_gtc_addr + 8 - (tramp + 13));
    g_real_gtc = (fnGetThreadContext)tramp;

    if (!install_jmp_hook(g_gtc_addr, (BYTE *)fake_gtc, g_gtc_orig, 8))
        return FALSE;

    log_write("X", "HOOK GTC @0x%p (DR0-7 gizlendi)", g_gtc_addr);
    return TRUE;
}

static void unhook_crdbp(void)
{
    if (!g_crdbp_addr) return;
    patch_bytes(g_crdbp_addr, g_crdbp_orig, 8);
    g_crdbp_addr = NULL;
}

static void unhook_getthreadcontext(void)
{
    if (!g_gtc_addr) return;
    patch_bytes(g_gtc_addr, g_gtc_orig, 8);
    g_gtc_addr = NULL;
}

// --- DR register proaktif temizligi ---

static void clear_all_dr_registers(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    DWORD myPid = GetCurrentProcessId();
    DWORD myTid = GetCurrentThreadId();
    THREADENTRY32 te = { .dwSize = sizeof(te) };
    int cleared = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != myPid) continue;
            if (te.th32ThreadID == myTid) continue;

            HANDLE hThread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);

            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            fnGetThreadContext realGtc = g_real_gtc ? g_real_gtc :
                (fnGetThreadContext)GetProcAddress(
                    GetModuleHandleA("kernel32.dll"), "GetThreadContext");

            if (realGtc && realGtc(hThread, &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7) {
                    ctx.Dr0 = 0; ctx.Dr1 = 0;
                    ctx.Dr2 = 0; ctx.Dr3 = 0;
                    ctx.Dr6 = 0; ctx.Dr7 = 0;
                    SetThreadContext(hThread, &ctx);
                    cleared++;
                }
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    if (cleared > 0)
        log_write("X", "DR cleared on %d threads", cleared);
}

// --- PEB/Heap patch ---

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

// --- NTDLL hook tespiti ---

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

// --- XIGNCODE modul taramasi ---

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

// --- VM/Sandbox DLL tespiti izleme ---

static void check_vm_indicators(void)
{
    const char *vmDlls[] = {
        "sbiedll.dll",
        "vboxhook.dll",
        "vmGuestLib.dll",
        NULL
    };

    for (int i = 0; vmDlls[i]; i++) {
        if (GetModuleHandleA(vmDlls[i])) {
            log_write("X", "VM DLL detected: %s", vmDlls[i]);
        }
    }
}

// --- Ana izleme thread'i ---

static DWORD WINAPI xmon_thread(LPVOID param)
{
    (void)param;

    scan_xign_modules();
    check_ntdll_hooks();
    check_vm_indicators();
    clear_all_dr_registers();

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

        if (cycle % 5 == 0)
            clear_all_dr_registers();

        if (cycle % 30 == 0)
            check_vm_indicators();

        for (int i = 0; i < 100 && g_xmon_running; i++)
            Sleep(100);
    }
    return 0;
}

// --- Public API ---

void xmon_start(void)
{
    if (g_xmon_running) return;

    hook_crdbp();
    hook_getthreadcontext();
    patch_peb_flags();

    g_xmon_running = TRUE;
    g_xmon_thread = CreateThread(NULL, 0, xmon_thread, NULL, 0, NULL);
    log_write("X", "xmon v2 started (CRDBP+GTC+DR+PEB)");
}

void xmon_stop(void)
{
    g_xmon_running = FALSE;

    unhook_crdbp();
    unhook_getthreadcontext();

    if (g_xmon_thread) {
        WaitForSingleObject(g_xmon_thread, 5000);
        CloseHandle(g_xmon_thread);
        g_xmon_thread = NULL;
    }
    log_write("X", "xmon stopped");
}
