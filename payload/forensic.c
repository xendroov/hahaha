#include "payload.h"
#include <string.h>

/*
 * Forensic Trace Cleanup
 *
 * XIGNCODE3 tespit vektorleri (kullanici raporundan):
 *
 *   1) PrefetchScanner:
 *      C:\Windows\Prefetch\*.pf dosyalarini okur.
 *      Debugger/hile acilip kapatilsa bile Prefetch izinden yakalar.
 *
 *   2) UjrScanner (USN Journal):
 *      NTFS $UsnJrnl degisim kaydini arastirir.
 *      Dosya silinse bile silme kaydini bulur.
 *
 *   3) IconResourceScanner:
 *      PE ikonunu hash'leyip karsilastirir.
 *      cheatengine.exe → notepad.exe olarak yeniden adlandirilsa bile
 *      ikon hash'inden yakalar.
 *
 *   4) AutoHotKeyScanner:
 *      AHK pencereleri, WH_KEYBOARD_LL hook'lari tarar.
 *
 *   5) DriverCollector:
 *      3. parti kernel suruculerini listeler.
 *
 * Bu modul:
 *   - Prefetch dosyalarini temizler (bilinen araclarin izleri)
 *   - USN Journal icin dosya operasyonlarini minimize eder
 *   - Injector PE kaynaklarini runtime'da strip eder
 */

static volatile BOOL g_forensic_running = FALSE;
static HANDLE g_forensic_thread = NULL;

static const char *g_prefetch_blacklist[] = {
    "CHEATENGINE",
    "X64DBG",
    "X32DBG",
    "OLLYDBG",
    "PROCESSHACKER",
    "LORDPE",
    "PETOOLS",
    "WINDBG",
    "KERNELSPY",
    "KERNELDETECTIVE",
    "SCYLLAHIDE",
    "INJECTOR",
    "MODSTOM",
    "THIJACK",
    "AUTOHOTKEY",
    "AHK",
    NULL
};

static int clean_prefetch(void)
{
    char prefetchDir[MAX_PATH];
    GetWindowsDirectoryA(prefetchDir, MAX_PATH);
    strcat(prefetchDir, "\\Prefetch\\");

    WIN32_FIND_DATAA fd;
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s*.pf", prefetchDir);

    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int deleted = 0;

    do {
        char upper[MAX_PATH];
        strncpy(upper, fd.cFileName, MAX_PATH - 1);
        upper[MAX_PATH - 1] = '\0';
        _strupr(upper);

        for (int i = 0; g_prefetch_blacklist[i]; i++) {
            if (strstr(upper, g_prefetch_blacklist[i])) {
                char fullPath[MAX_PATH];
                snprintf(fullPath, MAX_PATH, "%s%s", prefetchDir, fd.cFileName);

                if (DeleteFileA(fullPath)) {
                    deleted++;
                    log_write("F", "PF del: %s", fd.cFileName);
                }
                break;
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return deleted;
}

static void strip_pe_resources(const char *exePath)
{
    if (!exePath || !exePath[0]) return;

    HANDLE hUpdate = BeginUpdateResourceA(exePath, FALSE);
    if (!hUpdate) return;

    UpdateResourceA(hUpdate, RT_ICON, MAKEINTRESOURCEA(1), 0, NULL, 0);
    UpdateResourceA(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCEA(1), 0, NULL, 0);
    UpdateResourceA(hUpdate, RT_VERSION, MAKEINTRESOURCEA(1), 0, NULL, 0);

    if (EndUpdateResourceA(hUpdate, FALSE))
        log_write("F", "PE resources stripped: %s", exePath);
}

static void check_ahk_presence(void)
{
    const char *ahkClasses[] = {
        "AutoHotkey",
        "Aut2Exe",
        NULL
    };

    for (int i = 0; ahkClasses[i]; i++) {
        HWND hw = FindWindowA(ahkClasses[i], NULL);
        if (hw) {
            log_write("F", "AHK window found: %s (XIGNCODE will detect!)",
                      ahkClasses[i]);
        }
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            char upper[MAX_PATH];
            strncpy(upper, pe.szExeFile, MAX_PATH - 1);
            upper[MAX_PATH - 1] = '\0';
            _strupr(upper);
            if (strstr(upper, "AUTOHOTKEY") || strstr(upper, "AHK")) {
                log_write("F", "AHK process running: %s PID=%d (RISK!)",
                          pe.szExeFile, pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static void check_blacklisted_processes(void)
{
    const char *blacklist[] = {
        "CHEATENGINE", "CE",
        "X64DBG", "X32DBG",
        "OLLYDBG",
        "PROCESSHACKER",
        "WINDBG",
        "IDA", "IDAW",
        NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            char upper[MAX_PATH];
            strncpy(upper, pe.szExeFile, MAX_PATH - 1);
            upper[MAX_PATH - 1] = '\0';
            _strupr(upper);

            for (int i = 0; blacklist[i]; i++) {
                if (strstr(upper, blacklist[i])) {
                    log_write("F", "BLACKLISTED process: %s PID=%d",
                              pe.szExeFile, pe.th32ProcessID);
                    break;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static DWORD WINAPI forensic_thread(LPVOID param)
{
    (void)param;

    int pfDel = clean_prefetch();
    log_write("F", "prefetch cleanup: %d files", pfDel);

    check_ahk_presence();
    check_blacklisted_processes();

    DWORD cycle = 0;
    while (g_forensic_running) {
        cycle++;

        if (cycle % 12 == 0)
            clean_prefetch();

        if (cycle % 20 == 0) {
            check_ahk_presence();
            check_blacklisted_processes();
        }

        for (int i = 0; i < 100 && g_forensic_running; i++)
            Sleep(100);
    }
    return 0;
}

void forensic_start(void)
{
    if (g_forensic_running) return;
    g_forensic_running = TRUE;
    g_forensic_thread = CreateThread(NULL, 0, forensic_thread, NULL, 0, NULL);
    log_write("F", "forensic monitor started");
}

void forensic_stop(void)
{
    g_forensic_running = FALSE;
    if (g_forensic_thread) {
        WaitForSingleObject(g_forensic_thread, 5000);
        CloseHandle(g_forensic_thread);
        g_forensic_thread = NULL;
    }
    log_write("F", "forensic monitor stopped");
}

void forensic_strip_injector(const char *injectorPath)
{
    strip_pe_resources(injectorPath);
}
