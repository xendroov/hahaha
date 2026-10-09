// Packet Capture — CAPISocket::Send hook
//
// VEH INT3 hook at 0x00704070 (CAPISocket::Send, __thiscall)
// Captures plaintext packets BEFORE AES encryption.
//
// Packet format: [0xAA55][size:2][payload][0x55AA]
// Hook reads ECX (this ptr), ESP+4 (buffer), ESP+8 (length)

#include "payload.h"
#include <string.h>

#define CAPISOCKET_SEND  0x00704070
#define ENCRYPT_FLAG_ADDR 0x011159B4

static volatile BOOL g_pcap_active = FALSE;
static BYTE g_orig_byte = 0;
static PVOID g_veh_handle = NULL;
static DWORD g_pkt_count = 0;

static void dump_packet(const BYTE *buf, DWORD len)
{
    if (!buf || len == 0 || len > 0x10000) return;

    g_pkt_count++;

    DWORD showLen = len > 128 ? 128 : len;
    char hex[512] = {0};
    int pos = 0;
    for (DWORD i = 0; i < showLen && pos < (int)sizeof(hex) - 4; i++)
        pos += sprintf(hex + pos, "%02X ", buf[i]);
    if (len > showLen)
        pos += sprintf(hex + pos, "...");

    BYTE opcode = (len >= 3) ? buf[2] : 0;
    log_write("PCAP", "#%u len=%u op=0x%02X: %s",
              g_pkt_count, len, opcode, hex);
}

static LONG CALLBACK pcap_veh(PEXCEPTION_RECORD rec, PCONTEXT ctx)
{
    if (rec->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    if ((DWORD)rec->ExceptionAddress != CAPISOCKET_SEND)
        return EXCEPTION_CONTINUE_SEARCH;

    // __thiscall: ECX = this, stack: [retaddr][buf][len]
    DWORD *stack = (DWORD *)ctx->Esp;
    BYTE *buf = (BYTE *)stack[1];
    DWORD len = stack[2];

    dump_packet(buf, len);

    // Restore original byte, set TF for single-step re-arm
    *(BYTE *)CAPISOCKET_SEND = g_orig_byte;
    ctx->EFlags |= 0x100; // TF
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG CALLBACK pcap_ss_handler(PEXCEPTION_RECORD rec, PCONTEXT ctx)
{
    if (rec->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    // Re-arm INT3 after single-step
    if (g_pcap_active) {
        DWORD old;
        VirtualProtect((PVOID)CAPISOCKET_SEND, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE *)CAPISOCKET_SEND = 0xCC;
        VirtualProtect((PVOID)CAPISOCKET_SEND, 1, old, &old);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Combined VEH handler
static LONG CALLBACK pcap_veh_combined(PEXCEPTION_POINTERS ep)
{
    LONG r = pcap_veh(ep->ExceptionRecord, ep->ContextRecord);
    if (r != EXCEPTION_CONTINUE_SEARCH) return r;
    return pcap_ss_handler(ep->ExceptionRecord, ep->ContextRecord);
}

BOOL pcap_start(void)
{
    if (g_pcap_active) return TRUE;

    BYTE *target = (BYTE *)CAPISOCKET_SEND;

    // Verify target is accessible
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(target, &mbi, sizeof(mbi)))
        return FALSE;
    if (mbi.State != MEM_COMMIT)
        return FALSE;

    g_veh_handle = AddVectoredExceptionHandler(1, pcap_veh_combined);
    if (!g_veh_handle) return FALSE;

    // Save original byte and plant INT3
    DWORD old;
    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old);
    g_orig_byte = target[0];
    target[0] = 0xCC;
    VirtualProtect(target, 1, old, &old);

    g_pcap_active = TRUE;
    g_pkt_count = 0;
    log_write("PCAP", "Hook aktif @ 0x%08X (orig=0x%02X)", CAPISOCKET_SEND, g_orig_byte);
    return TRUE;
}

void pcap_stop(void)
{
    if (!g_pcap_active) return;
    g_pcap_active = FALSE;

    // Restore original byte
    BYTE *target = (BYTE *)CAPISOCKET_SEND;
    DWORD old;
    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old);
    target[0] = g_orig_byte;
    VirtualProtect(target, 1, old, &old);

    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }

    log_write("PCAP", "Hook kaldirildi, toplam %u paket yakalandi", g_pkt_count);
}
