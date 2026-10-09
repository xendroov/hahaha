// Packet Capture — CAPISocket::Send + Recv hook
//
// VEH INT3 hook:
//   Send:  KO_SND_FNC  (0x007032E0) — __thiscall
//   Recv:  KO_RECV_FNC (0x0084C700) — paket isleme
//
// Plaintext paketleri sifreleme oncesi yakalar.
// Packet format: [0xAA55][size:2][payload][0x55AA]

#include "payload.h"
#include <string.h>

static volatile BOOL g_pcap_active = FALSE;
static BYTE g_orig_send = 0;
static BYTE g_orig_recv = 0;
static PVOID g_veh_handle = NULL;
static DWORD g_snd_count = 0;
static DWORD g_rcv_count = 0;

static void dump_packet(const char *dir, DWORD *counter,
                        const BYTE *buf, DWORD len)
{
    if (!buf || len == 0 || len > 0x10000) return;
    (*counter)++;

    DWORD showLen = len > 128 ? 128 : len;
    char hex[512] = {0};
    int pos = 0;
    for (DWORD i = 0; i < showLen && pos < (int)sizeof(hex) - 4; i++)
        pos += sprintf(hex + pos, "%02X ", buf[i]);
    if (len > showLen)
        pos += sprintf(hex + pos, "...");

    BYTE opcode = (len >= 3) ? buf[2] : 0;
    log_write("PCAP", "[%s] #%u len=%u op=0x%02X: %s",
              dir, *counter, len, opcode, hex);
}

static LONG CALLBACK pcap_veh_handler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    PCONTEXT ctx = ep->ContextRecord;

    // --- INT3 handler ---
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) {
        DWORD addr = (DWORD)rec->ExceptionAddress;

        if (addr == KO_SND_FNC) {
            // __thiscall: ECX=this, stack: [retaddr][buf][len]
            DWORD *stack = (DWORD *)ctx->Esp;
            BYTE *buf = (BYTE *)stack[1];
            DWORD len = stack[2];
            dump_packet("SND", &g_snd_count, buf, len);

            *(BYTE *)KO_SND_FNC = g_orig_send;
            ctx->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (addr == KO_RECV_FNC) {
            DWORD *stack = (DWORD *)ctx->Esp;
            BYTE *buf = (BYTE *)stack[1];
            DWORD len = stack[2];
            dump_packet("RCV", &g_rcv_count, buf, len);

            *(BYTE *)KO_RECV_FNC = g_orig_recv;
            ctx->EFlags |= 0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    // --- Single-step: re-arm INT3 ---
    if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP && g_pcap_active) {
        DWORD old;
        VirtualProtect((PVOID)KO_SND_FNC, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE *)KO_SND_FNC = 0xCC;
        VirtualProtect((PVOID)KO_SND_FNC, 1, old, &old);

        VirtualProtect((PVOID)KO_RECV_FNC, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE *)KO_RECV_FNC = 0xCC;
        VirtualProtect((PVOID)KO_RECV_FNC, 1, old, &old);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL hook_one(DWORD addr, BYTE *orig_out)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((PVOID)addr, &mbi, sizeof(mbi)))
        return FALSE;
    if (mbi.State != MEM_COMMIT)
        return FALSE;

    DWORD old;
    VirtualProtect((PVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *orig_out = *(BYTE *)addr;
    *(BYTE *)addr = 0xCC;
    VirtualProtect((PVOID)addr, 1, old, &old);
    return TRUE;
}

static void unhook_one(DWORD addr, BYTE orig)
{
    DWORD old;
    VirtualProtect((PVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE *)addr = orig;
    VirtualProtect((PVOID)addr, 1, old, &old);
}

BOOL pcap_start(void)
{
    if (g_pcap_active) return TRUE;

    g_veh_handle = AddVectoredExceptionHandler(1, pcap_veh_handler);
    if (!g_veh_handle) return FALSE;

    BOOL snd_ok = hook_one(KO_SND_FNC, &g_orig_send);
    BOOL rcv_ok = hook_one(KO_RECV_FNC, &g_orig_recv);

    if (!snd_ok && !rcv_ok) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
        return FALSE;
    }

    g_pcap_active = TRUE;
    g_snd_count = 0;
    g_rcv_count = 0;

    log_write("PCAP", "Send hook: %s @ 0x%08X (orig=0x%02X)",
              snd_ok ? "OK" : "FAIL", KO_SND_FNC, g_orig_send);
    log_write("PCAP", "Recv hook: %s @ 0x%08X (orig=0x%02X)",
              rcv_ok ? "OK" : "FAIL", KO_RECV_FNC, g_orig_recv);
    return TRUE;
}

void pcap_stop(void)
{
    if (!g_pcap_active) return;
    g_pcap_active = FALSE;

    unhook_one(KO_SND_FNC, g_orig_send);
    unhook_one(KO_RECV_FNC, g_orig_recv);

    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }

    log_write("PCAP", "Hooklar kaldirildi — SND:%u RCV:%u paket",
              g_snd_count, g_rcv_count);
}
