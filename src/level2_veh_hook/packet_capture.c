// Level 2 — VEH Hook ile Paket Yakalama
//
// CAPISocket::Send (0x704070) fonksiyonunu VEH hook ile izler.
// ntdll'e dokunmaz, oyun fonksiyonunda sadece 1 byte (0xCC) değişir.
//
// XIGNCODE'un ntdll integrity check'i bunu görmez — farklı adres alanı.
// Ancak Themida'nın kendi CRC check'i oyun .text section'ını tarıyorsa
// 1-byte değişikliği yakalayabilir.
//
// Güvenli alternatif: Hardware breakpoint (hwbp_hook_install) — 0 byte değişiklik
// Risk: NtGetContextThread ile DR taraması (%20 olasılık)

#include "veh_hook.h"
#include <stdio.h>
#include <time.h>

#define SEND_FUNC_ADDR 0x00704070  // CAPISocket::Send (RVA-aware olmalı)
#define MAX_PACKET_LOG 10000

// Paket log yapısı
typedef struct {
    DWORD tick;
    DWORD size;
    BYTE header[32]; // ilk 32 byte
} PACKET_LOG_ENTRY;

static PACKET_LOG_ENTRY g_packets[MAX_PACKET_LOG];
static volatile LONG g_packet_count = 0;
static FILE *g_packet_log = NULL;
static BOOL g_use_hwbp = FALSE; // TRUE = hardware breakpoint, FALSE = INT3

// __thiscall convention: ECX = this pointer
// Stack: [return_addr] [arg1: buffer] [arg2: size] ...
// CAPISocket::Send imzası (analiz #12'den):
//   void __thiscall CAPISocket::Send(BYTE *buffer, int size)
static void on_send_packet(PCONTEXT ctx, void *user_data)
{
    // __thiscall: ECX = this (CAPISocket*), stack parametreleri:
    // ESP+4 = buffer pointer (return address ESP+0 zaten handler'da)
    // ESP+8 = size
    //
    // VEH handler'da ESP, çağrı anındaki ESP'dir.
    // Return address henüz push'lanmıştır.
    DWORD esp = ctx->Esp;
    DWORD *stack = (DWORD *)esp;

    BYTE *buffer = (BYTE *)stack[1]; // ilk parametre (return addr'den sonra)
    int size = (int)stack[2];        // ikinci parametre

    if (size <= 0 || size > 65536) return;
    if (IsBadReadPtr(buffer, size)) return;

    LONG idx = InterlockedIncrement(&g_packet_count) - 1;
    if (idx >= MAX_PACKET_LOG) return;

    g_packets[idx].tick = GetTickCount();
    g_packets[idx].size = size;

    int copyLen = (size < 32) ? size : 32;
    memcpy(g_packets[idx].header, buffer, copyLen);

    // Real-time log
    if (g_packet_log) {
        fprintf(g_packet_log, "[%08X] SEND size=%d: ", g_packets[idx].tick, size);
        for (int i = 0; i < copyLen; i++) {
            fprintf(g_packet_log, "%02X ", buffer[i]);
        }
        fprintf(g_packet_log, "\n");
        fflush(g_packet_log);
    }
}

// --- Public API ---

BOOL packet_capture_start(const char *logPath, BOOL useHardwareBP)
{
    g_use_hwbp = useHardwareBP;
    g_packet_count = 0;

    g_packet_log = fopen(logPath, "w");
    if (!g_packet_log) return FALSE;

    fprintf(g_packet_log, "=== Packet Capture (Level 2: %s) ===\n",
        g_use_hwbp ? "Hardware BP" : "VEH INT3");
    fprintf(g_packet_log, "Target: CAPISocket::Send @ 0x%08X\n\n", SEND_FUNC_ADDR);

    PVOID target = (PVOID)(ULONG_PTR)SEND_FUNC_ADDR;

    BOOL ok;
    if (g_use_hwbp) {
        ok = hwbp_hook_install(target, on_send_packet, NULL);
        fprintf(g_packet_log, "HWBP hook: %s\n", ok ? "OK" : "FAILED");
    } else {
        ok = veh_hook_install(target, on_send_packet, NULL);
        fprintf(g_packet_log, "VEH hook: %s\n", ok ? "OK" : "FAILED");
    }

    return ok;
}

void packet_capture_stop(void)
{
    PVOID target = (PVOID)(ULONG_PTR)SEND_FUNC_ADDR;

    if (g_use_hwbp) {
        hwbp_hook_remove(target);
    } else {
        veh_hook_remove(target);
    }

    if (g_packet_log) {
        fprintf(g_packet_log, "\n=== Capture stopped. %d packets logged. ===\n",
            (int)g_packet_count);
        fclose(g_packet_log);
        g_packet_log = NULL;
    }
}

// Yakalanan paketlerin istatistiklerini döndür
void packet_capture_stats(int *total, int *perSecond)
{
    *total = (int)g_packet_count;
    // TODO: zaman aralığından hesapla
    *perSecond = 0;
}
