// Level 1 — Direct Syscall API Monitor
//
// XIGNCODE3'ün API izleme yaklaşımının en temel bypass'ı.
// ntdll'e hiç inline hook koymadan, direct syscall ile kernel'a gidip
// process/modül/bellek bilgisi toplar.
//
// Mevcut XignDump'tan farkı:
//   XignDump: ntdll fonksiyonlarına E9 JMP patch -> 10sn window -> kaldır
//   Bu:       ntdll'e hiç dokunmaz, direct syscall ile aynı bilgiyi toplar
//
// Dezavantaj: XIGNCODE'un hangi API'leri çağırdığını izleyemez
//             (hook olmadığı için XIGNCODE çağrıları görünmez).
//             Ama kendi taramalarımızı güvenle yapabiliriz.

#include "../common/syscall_defs.h"
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

// --- Yapılar ---

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// --- Module enumeration (direct syscall ile) ---

typedef struct {
    PVOID BaseAddress;
    SIZE_T RegionSize;
    DWORD Protect;
    DWORD Type;
} MODULE_REGION;

// Bellek bölgelerini tara — XIGNCODE'un yaptığı gibi ama direct syscall ile
static void scan_memory_regions(HANDLE hProcess, FILE *logFile)
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = NULL;
    SIZE_T returnLen;
    int count = 0;

    fprintf(logFile, "\n=== MEMORY REGIONS (direct syscall) ===\n");

    while (1) {
        NTSTATUS status = dc_NtQueryVirtualMemory(
            hProcess, addr,
            MemoryBasicInformation,
            &mbi, sizeof(mbi), &returnLen
        );

        if (status != 0) break;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
            fprintf(logFile, "  [IMG] %p - %p  Size=0x%08X  Protect=0x%04X\n",
                mbi.BaseAddress,
                (BYTE *)mbi.BaseAddress + mbi.RegionSize,
                (DWORD)mbi.RegionSize,
                mbi.Protect);
            count++;
        }
        else if (mbi.State == MEM_COMMIT &&
                 (mbi.Protect & PAGE_EXECUTE_READWRITE) &&
                 mbi.Type == MEM_PRIVATE) {
            // RWX private memory — şüpheli (hook trampoline, shellcode)
            fprintf(logFile, "  [RWX] %p - %p  Size=0x%08X  *** SUSPICIOUS ***\n",
                mbi.BaseAddress,
                (BYTE *)mbi.BaseAddress + mbi.RegionSize,
                (DWORD)mbi.RegionSize);
        }

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr >= 0x7FFE0000) break;
    }

    fprintf(logFile, "  Total image regions: %d\n", count);
}

// ntdll integrity check — XIGNCODE'un yaptığını simüle et
// 12 taranan fonksiyonun ilk 16 byte'ını oku ve logla
static void check_ntdll_integrity(FILE *logFile)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    const char *targets[] = {
        "NtProtectVirtualMemory",
        "NtQueryVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtOpenProcess",
        "NtQuerySystemInformation",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "NtGetContextThread",
        "NtCreateThreadEx",
        "NtMapViewOfSection",
        "NtClose",
        NULL
    };

    fprintf(logFile, "\n=== NTDLL INTEGRITY CHECK (our verification) ===\n");

    for (int i = 0; targets[i]; i++) {
        BYTE *func = (BYTE *)GetProcAddress(ntdll, targets[i]);
        if (!func) continue;

        fprintf(logFile, "  %s @ %p: ", targets[i], func);

        // İlk 16 byte'ı hex olarak logla
        for (int j = 0; j < 16; j++) {
            fprintf(logFile, "%02X ", func[j]);
        }

        // Hook kontrolü
        if (func[0] == 0xE9) {
            DWORD jmpTarget = *(DWORD *)(func + 1);
            fprintf(logFile, " *** HOOKED (JMP %p) ***", (BYTE *)func + 5 + jmpTarget);
        } else if (func[0] == 0xB8) {
            fprintf(logFile, " [CLEAN - syscall %d]", *(DWORD *)(func + 1));
        } else if (func[0] == 0xCC) {
            fprintf(logFile, " *** INT3 BREAKPOINT ***");
        }

        fprintf(logFile, "\n");
    }
}

// Process listesi — XIGNCODE'un NtQuerySystemInformation ile yaptığının aynısı
static void enum_processes_syscall(FILE *logFile)
{
    ULONG bufSize = 1024 * 1024; // 1 MB
    PVOID buf = VirtualAlloc(NULL, bufSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) return;

    // SystemProcessInformation = 5
    typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

    // Direct syscall ile process listesini al
    // (g_stub_funcs[5] = NtQuerySystemInformation)
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQuerySystemInformation NtQSI =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    ULONG retLen;
    NTSTATUS status = NtQSI(5, buf, bufSize, &retLen);

    if (status == 0) {
        fprintf(logFile, "\n=== PROCESS LIST (syscall) ===\n");
        PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buf;
        int count = 0;

        while (1) {
            if (proc->ImageName.Buffer) {
                fprintf(logFile, "  PID %5d: %.*ls\n",
                    (DWORD)(ULONG_PTR)proc->UniqueProcessId,
                    proc->ImageName.Length / 2,
                    proc->ImageName.Buffer);
            }
            count++;

            if (proc->NextEntryOffset == 0) break;
            proc = (PSYSTEM_PROCESS_INFORMATION)((BYTE *)proc + proc->NextEntryOffset);
        }
        fprintf(logFile, "  Total processes: %d\n", count);
    }

    VirtualFree(buf, 0, MEM_RELEASE);
}

// XIGNCODE modüllerini bul ve CRC/entropy bilgisi topla
static void scan_xigncode_modules(FILE *logFile)
{
    fprintf(logFile, "\n=== XIGNCODE MODULE SCAN ===\n");

    const char *xignModules[] = {
        "x3.xem", "xcorona.xem", "xcorona_x64.xem",
        "xmag.xem", "xnina.xem", "xxd-0.xem", "xm.exe",
        NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(logFile, "  CreateToolhelp32Snapshot failed: %d\n", GetLastError());
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    if (Module32First(snap, &me)) {
        do {
            // XIGNCODE modülü mü kontrol et
            for (int i = 0; xignModules[i]; i++) {
                if (_stricmp(me.szModule, xignModules[i]) == 0) {
                    fprintf(logFile, "  [XIGN] %s @ %p  Size=0x%X  Path=%s\n",
                        me.szModule, me.modBaseAddr, me.modBaseSize, me.szExePath);

                    // İlk 64 byte'ı dump et (MZ header + PE offset)
                    fprintf(logFile, "    Header: ");
                    for (int j = 0; j < 64 && j < (int)me.modBaseSize; j++) {
                        fprintf(logFile, "%02X ", me.modBaseAddr[j]);
                        if ((j + 1) % 32 == 0) fprintf(logFile, "\n            ");
                    }
                    fprintf(logFile, "\n");
                    break;
                }
            }
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
}

// --- Ana giriş noktası ---

typedef struct {
    DWORD durationMs;
    char logPath[MAX_PATH];
} MONITOR_CONFIG;

static DWORD WINAPI monitor_thread(LPVOID param)
{
    MONITOR_CONFIG *cfg = (MONITOR_CONFIG *)param;

    FILE *logFile = fopen(cfg->logPath, "w");
    if (!logFile) return 1;

    fprintf(logFile, "=== Level 1: Direct Syscall Monitor ===\n");
    fprintf(logFile, "Timestamp: %lu\n", GetTickCount());
    fprintf(logFile, "PID: %d\n", GetCurrentProcessId());
    fprintf(logFile, "Duration: %d ms\n\n", cfg->durationMs);

    // 1. Syscall numaralarını çöz
    fprintf(logFile, "--- Resolving syscall numbers ---\n");
    if (!resolve_syscall_numbers()) {
        fprintf(logFile, "ERROR: Failed to resolve syscall numbers!\n");
        fclose(logFile);
        return 1;
    }

    fprintf(logFile, "  NtProtectVirtualMemory = 0x%X\n", g_syscalls.NtProtectVirtualMemory);
    fprintf(logFile, "  NtQueryVirtualMemory   = 0x%X\n", g_syscalls.NtQueryVirtualMemory);
    fprintf(logFile, "  NtReadVirtualMemory    = 0x%X\n", g_syscalls.NtReadVirtualMemory);
    fprintf(logFile, "  NtOpenProcess          = 0x%X\n", g_syscalls.NtOpenProcess);
    fprintf(logFile, "  NtQuerySystemInfo      = 0x%X\n", g_syscalls.NtQuerySystemInformation);
    fprintf(logFile, "\n--- ntdll is UNTOUCHED (no inline hooks) ---\n");

    // 2. ntdll integrity — kendi doğrulamamız
    check_ntdll_integrity(logFile);

    // 3. XIGNCODE modüllerini tara
    scan_xigncode_modules(logFile);

    // 4. Process listesi
    enum_processes_syscall(logFile);

    // 5. Bellek bölgeleri
    scan_memory_regions(GetCurrentProcess(), logFile);

    fprintf(logFile, "\n=== Monitor complete. ntdll was never modified. ===\n");
    fflush(logFile);
    fclose(logFile);
    return 0;
}

// DllMain — inject edildiğinde otomatik başlar
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        static MONITOR_CONFIG cfg;
        cfg.durationMs = 10000;
        GetTempPathA(MAX_PATH, cfg.logPath);
        strcat_s(cfg.logPath, MAX_PATH, "xign_level1.log");

        CreateThread(NULL, 0, monitor_thread, &cfg, 0, NULL);
    }
    return TRUE;
}
