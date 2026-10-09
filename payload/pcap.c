#include "payload.h"
#include <string.h>

/*
 * Packet Capture — KO send/recv hook
 *
 * KO_SND_FNC (0x007032E0): oyunun paket gonderme fonksiyonu
 * KO_RECV_FNC (0x0084C700): oyunun paket alma fonksiyonu
 *
 * Her iki fonksiyon inline hook ile yakalanir, ilk N byte
 * trampoline'a kopyalanir, oradan orijinale geri atlanir.
 */

typedef void (__stdcall *fnSend)(BYTE *pkt, int len);
typedef void (__stdcall *fnRecv)(BYTE *pkt, int len);

static BYTE g_sndOrig[16];
static BYTE g_rcvOrig[16];
static BYTE *g_sndTramp = NULL;
static BYTE *g_rcvTramp = NULL;
static volatile BOOL g_pcap_running = FALSE;

static void log_packet(const char *dir, BYTE *pkt, int len)
{
    if (!pkt || len <= 0) return;

    int show = len > 32 ? 32 : len;
    char hex[200];
    int pos = 0;

    for (int i = 0; i < show && pos < (int)sizeof(hex) - 4; i++)
        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X ", pkt[i]);

    if (len > show)
        snprintf(hex + pos, sizeof(hex) - pos, "...");

    log_write("P", "%s %d: %s", dir, len, hex);
}

static BYTE *make_trampoline(BYTE *target, BYTE *backup, int patchLen)
{
    BYTE *tramp = (BYTE *)VirtualAlloc(NULL, 32,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!tramp) return NULL;

    memcpy(backup, target, patchLen);
    memcpy(tramp, target, patchLen);

    tramp[patchLen] = 0xE9;
    *(DWORD *)(tramp + patchLen + 1) =
        (DWORD)(target + patchLen - (tramp + patchLen + 5));

    return tramp;
}

static BOOL install_hook(BYTE *target, BYTE *detour, int patchLen)
{
    DWORD old;
    if (!VirtualProtect(target, patchLen, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;

    target[0] = 0xE9;
    *(DWORD *)(target + 1) = (DWORD)(detour - target - 5);

    for (int i = 5; i < patchLen; i++)
        target[i] = 0x90;

    VirtualProtect(target, patchLen, old, &old);
    return TRUE;
}

static void remove_hook(BYTE *target, BYTE *backup, int patchLen)
{
    DWORD old;
    if (VirtualProtect(target, patchLen, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(target, backup, patchLen);
        VirtualProtect(target, patchLen, old, &old);
    }
}

static void __declspec(naked) snd_hook(void)
{
    __asm {
        pushad
        pushfd

        mov eax, [esp + 0x28]
        mov edx, [esp + 0x2C]
        push edx
        push eax
        push offset snd_tag
        call log_packet_asm
        add esp, 12

        popfd
        popad
        jmp [g_sndTramp]

    snd_tag:
        __emit 'S'
        __emit 'N'
        __emit 'D'
        __emit 0
    }
}

static void __declspec(naked) rcv_hook(void)
{
    __asm {
        pushad
        pushfd

        mov eax, [esp + 0x28]
        mov edx, [esp + 0x2C]
        push edx
        push eax
        push offset rcv_tag
        call log_packet_asm
        add esp, 12

        popfd
        popad
        jmp [g_rcvTramp]

    rcv_tag:
        __emit 'R'
        __emit 'C'
        __emit 'V'
        __emit 0
    }
}

static void __cdecl log_packet_asm(const char *dir, BYTE *pkt, int len)
{
    if (g_pcap_running)
        log_packet(dir, pkt, len);
}

BOOL pcap_start(void)
{
    if (g_pcap_running) return TRUE;

    BYTE *sndAddr = (BYTE *)KO_SND_FNC;
    BYTE *rcvAddr = (BYTE *)KO_RECV_FNC;

    __try {
        volatile BYTE test = sndAddr[0];
        test = rcvAddr[0];
        (void)test;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_write("P", "target addr invalid");
        return FALSE;
    }

    g_sndTramp = make_trampoline(sndAddr, g_sndOrig, 7);
    g_rcvTramp = make_trampoline(rcvAddr, g_rcvOrig, 7);

    if (!g_sndTramp || !g_rcvTramp) {
        log_write("P", "trampoline alloc failed");
        return FALSE;
    }

    g_pcap_running = TRUE;

    if (!install_hook(sndAddr, (BYTE *)snd_hook, 7)) {
        log_write("P", "SND hook failed");
        g_pcap_running = FALSE;
        return FALSE;
    }

    if (!install_hook(rcvAddr, (BYTE *)rcv_hook, 7)) {
        remove_hook(sndAddr, g_sndOrig, 7);
        log_write("P", "RCV hook failed");
        g_pcap_running = FALSE;
        return FALSE;
    }

    log_write("P", "pcap started SND@%p RCV@%p", sndAddr, rcvAddr);
    return TRUE;
}

void pcap_stop(void)
{
    if (!g_pcap_running) return;
    g_pcap_running = FALSE;

    Sleep(100);

    remove_hook((BYTE *)KO_SND_FNC, g_sndOrig, 7);
    remove_hook((BYTE *)KO_RECV_FNC, g_rcvOrig, 7);

    if (g_sndTramp) { VirtualFree(g_sndTramp, 0, MEM_RELEASE); g_sndTramp = NULL; }
    if (g_rcvTramp) { VirtualFree(g_rcvTramp, 0, MEM_RELEASE); g_rcvTramp = NULL; }

    log_write("P", "pcap stopped");
}
