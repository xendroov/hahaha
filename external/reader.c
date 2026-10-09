#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <tlhelp32.h>

/*
 * External game state reader — XIGNCODE3 bypass
 *
 * Oyun icine HICBIR SEY enjekte etmez. DLL yok, hook yok, modul yok.
 * CreateProcess ile oyunu baslatir, PROCESS_ALL_ACCESS handle alir.
 * XIGNCODE'un kernel driver'i (ObRegisterCallbacks) sadece YENI handle
 * acmalarini yakalar — bizim handle process yaratildiginda zaten verildi,
 * driver yuklenmeden ONCE. ReadProcessMemory ile disaridan okuyoruz.
 *
 * Kullanim:
 *   reader.exe "C:\KO\KnightOnLine.exe"          (oyunu baslatir)
 *   reader.exe --watch                            (oyunu bekler, hizli attach)
 */

/* ---- KO offset tablosu ---- */
#define KO_PTR_CHR          0x01115574

#define KO_OFF_ID           0x000006A0
#define KO_OFF_NAME         0x000006A4
#define KO_OFF_NATION       0x000006C4
#define KO_OFF_RACE         0x000006C0
#define KO_OFF_CLASS        0x000006CC
#define KO_OFF_LEVEL        0x000006D0
#define KO_OFF_MAXHP        0x000006D4
#define KO_OFF_HP           0x000006D8
#define KO_OFF_MAX_MP       0x00000BEC
#define KO_OFF_MP           0x00000BF0
#define KO_OFF_GOLD         0x00000BFC
#define KO_OFF_POSX         0x000003CC
#define KO_OFF_POSY         0x000003D4
#define KO_OFF_POSZ         0x00000194
#define KO_OFF_TARGET       0x00000660

/* ---- Globals ---- */
static HANDLE   g_proc    = NULL;
static DWORD    g_pid     = 0;
static volatile BOOL g_running = TRUE;
static FILE    *g_log     = NULL;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    g_running = FALSE;
    return TRUE;
}

/* ---- Logging ---- */
static void logf(const char *cat, const char *fmt, ...)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    char ts[32];
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list ap;

    if (g_log) {
        fprintf(g_log, "[%s][%s] ", ts, cat);
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fprintf(g_log, "\n");
        fflush(g_log);
    }

    printf("[%s][%s] ", ts, cat);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

/* ---- Memory reading ---- */
static BOOL rpm(DWORD addr, void *buf, SIZE_T sz)
{
    SIZE_T n = 0;
    return ReadProcessMemory(g_proc, (LPCVOID)(ULONG_PTR)addr,
                             buf, sz, &n) && n == sz;
}

static DWORD rd(DWORD addr)
{
    DWORD v = 0;
    rpm(addr, &v, 4);
    return v;
}

static float rf(DWORD addr)
{
    float v = 0.0f;
    rpm(addr, &v, 4);
    return v;
}

/* ---- Game state dump ---- */
static void dump_state(void)
{
    DWORD base = rd(KO_PTR_CHR);
    if (!base) {
        logf("G", "-");
        return;
    }

    DWORD id     = rd(base + KO_OFF_ID);
    DWORD cls    = rd(base + KO_OFF_CLASS);
    DWORD level  = rd(base + KO_OFF_LEVEL);
    DWORD nation = rd(base + KO_OFF_NATION);
    DWORD race   = rd(base + KO_OFF_RACE);

    char name[32] = {0};
    rpm(base + KO_OFF_NAME, name, sizeof(name) - 1);

    DWORD hp    = rd(base + KO_OFF_HP);
    DWORD maxhp = rd(base + KO_OFF_MAXHP);
    DWORD mp    = rd(base + KO_OFF_MP);
    DWORD maxmp = rd(base + KO_OFF_MAX_MP);
    DWORD gold  = rd(base + KO_OFF_GOLD);

    float px = rf(base + KO_OFF_POSX);
    float py = rf(base + KO_OFF_POSY);
    float pz = rf(base + KO_OFF_POSZ);

    DWORD tgt = rd(base + KO_OFF_TARGET);

    logf("G", "%s [%u] Lv%u C:%u N:%u R:%u",
         name, id, level, cls, nation, race);
    logf("G", "  HP:%u/%u MP:%u/%u G:%u",
         hp, maxhp, mp, maxmp, gold);
    logf("G", "  P:%.1f,%.1f,%.1f T:%u",
         px, py, pz, tgt);
}

/* ---- Process search ---- */
static DWORD find_ko(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            _strlwr(pe.szExeFile);
            if (strstr(pe.szExeFile, "knightonline"))
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ---- Launch mode: CreateProcess ---- */
static BOOL launch_game(const char *path)
{
    char gameDir[MAX_PATH];
    strncpy(gameDir, path, MAX_PATH - 1);
    gameDir[MAX_PATH - 1] = '\0';

    char *sep = strrchr(gameDir, '\\');
    if (!sep) sep = strrchr(gameDir, '/');
    if (sep) *sep = '\0';
    else     strcpy(gameDir, ".");

    char cmdLine[4096];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", path);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL,
                        FALSE, 0, NULL, gameDir, &si, &pi))
    {
        printf("[!] CreateProcess failed: %u\n", GetLastError());
        return FALSE;
    }

    g_proc = pi.hProcess;
    g_pid  = pi.dwProcessId;
    CloseHandle(pi.hThread);

    printf("[+] Game launched  PID %u\n", g_pid);
    printf("[+] Handle acquired BEFORE XIGNCODE driver load\n");
    printf("[+] ObRegisterCallbacks cannot strip this handle\n\n");
    return TRUE;
}

/* ---- Watch mode: poll until game appears, grab handle instantly ---- */
static BOOL watch_game(void)
{
    printf("[*] Waiting for KnightOnLine process...\n");
    printf("[*] Launch the game normally. We will grab the handle.\n\n");

    while (g_running) {
        DWORD pid = find_ko();
        if (pid) {
            g_proc = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE, pid);

            if (g_proc) {
                g_pid = pid;
                printf("[+] Attached to PID %u\n", pid);
                return TRUE;
            }

            printf("[!] OpenProcess failed: %u\n", GetLastError());
            printf("[!] XIGNCODE driver already blocked handle.\n");
            printf("[!] Use launch mode instead: reader.exe <game path>\n");
            return FALSE;
        }
        Sleep(50);
    }
    return FALSE;
}

/* ---- Main ---- */
int main(int argc, char **argv)
{
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    printf("=== KO External Reader ===\n");
    printf("No injection. No DLL. Pure external read.\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  reader.exe \"C:\\KO\\KnightOnLine.exe\"   (launch mode)\n");
        printf("  reader.exe --watch                      (attach mode)\n");
        return 1;
    }

    BOOL ok;
    if (_stricmp(argv[1], "--watch") == 0)
        ok = watch_game();
    else
        ok = launch_game(argv[1]);

    if (!ok) return 1;

    /* Log file */
    char tmp[MAX_PATH], logPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    snprintf(logPath, MAX_PATH, "%sdi_%u.tmp", tmp, g_pid);
    g_log = fopen(logPath, "w");
    printf("[+] Log: %s\n\n", logPath);

    /* Wait for game to initialize */
    printf("[*] Waiting 15s for game init...\n");
    for (int i = 0; i < 150 && g_running; i++)
        Sleep(100);

    logf("R", "PID:%u", g_pid);

    /* Main loop */
    while (g_running) {
        DWORD exitCode = 0;
        if (!GetExitCodeProcess(g_proc, &exitCode) ||
            exitCode != STILL_ACTIVE)
        {
            logf("R", "Game exited (%u)", exitCode);
            break;
        }

        dump_state();

        for (int i = 0; i < 10 && g_running; i++)
            Sleep(100);
    }

    if (g_log) fclose(g_log);
    if (g_proc) CloseHandle(g_proc);
    printf("\nDone.\n");
    return 0;
}
