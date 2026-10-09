// Merkezi log sistemi
// Tüm modüller (xmon, pcap, gstate) bu üzerinden yazar.
// Thread-safe, auto-flush.

#include "payload.h"

static FILE *g_log = NULL;
static CRITICAL_SECTION g_logLock;
static BOOL g_logReady = FALSE;

void log_init(const char *path)
{
    if (g_logReady) return;
    InitializeCriticalSection(&g_logLock);
    g_log = fopen(path, "w");
    g_logReady = TRUE;
}

void log_close(void)
{
    if (!g_logReady) return;
    g_logReady = FALSE;
    EnterCriticalSection(&g_logLock);
    if (g_log) { fclose(g_log); g_log = NULL; }
    LeaveCriticalSection(&g_logLock);
    DeleteCriticalSection(&g_logLock);
}

void log_write(const char *category, const char *fmt, ...)
{
    if (!g_logReady || !g_log) return;

    EnterCriticalSection(&g_logLock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d][%s] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, category);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);

    fprintf(g_log, "\n");
    fflush(g_log);

    LeaveCriticalSection(&g_logLock);
}
