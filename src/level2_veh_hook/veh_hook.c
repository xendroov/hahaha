#include "veh_hook.h"
#include "../common/syscall_defs.h"
#include <stdio.h>

static VEH_HOOK_ENTRY g_hooks[MAX_VEH_HOOKS] = {0};
static PVOID g_veh_handle = NULL;
static int g_hook_count = 0;

// --- VEH Handler ---
// Her INT3 exception'ında çağrılır.
// Bizim hook'ladığımız adreslerden biriyse callback'i çağırıp devam et.
static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID addr = ep->ExceptionRecord->ExceptionAddress;

    for (int i = 0; i < g_hook_count; i++) {
        if (!g_hooks[i].active) continue;
        if (g_hooks[i].target_addr != addr) continue;

        // Orijinal byte'ı geri yaz (tek seferlik çalıştırma için)
        DWORD oldProt;
        VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
        *(BYTE *)addr = g_hooks[i].original_byte;
        VirtualProtect(addr, 1, oldProt, &oldProt);

        // Callback çağır — ctx üzerinden register'ları okuyabilir/değiştirebilir
        if (g_hooks[i].callback) {
            g_hooks[i].callback(ep->ContextRecord, g_hooks[i].user_data);
        }

        // Single-step flag (TF) — bir instruction çalıştıktan sonra
        // tekrar exception oluşur, orada INT3'ü geri koyarız
        ep->ContextRecord->EFlags |= 0x100; // TF (Trap Flag)

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Single-step exception handler — INT3'ü geri koy
static LONG CALLBACK veh_single_step_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    // Orijinal instruction çalıştı, şimdi INT3'ü geri koy
    for (int i = 0; i < g_hook_count; i++) {
        if (!g_hooks[i].active) continue;

        // EIP, hedef fonksiyonun 2. instruction'ında mı kontrol et
        // (orijinal ilk instruction çalışmış, EIP ilerlemiş olmalı)
        BYTE *target = (BYTE *)g_hooks[i].target_addr;
        DWORD eip = ep->ContextRecord->Eip;

        // Hedef adresten en fazla 16 byte ileride olmalı
        if (eip > (DWORD)(ULONG_PTR)target &&
            eip <= (DWORD)(ULONG_PTR)target + 16) {

            DWORD oldProt;
            VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
            *target = 0xCC;
            VirtualProtect(target, 1, oldProt, &oldProt);

            ep->ContextRecord->EFlags &= ~0x100; // TF temizle
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL veh_hook_init(void)
{
    if (g_veh_handle) return TRUE;

    // İlk handler: INT3 yakalama
    g_veh_handle = AddVectoredExceptionHandler(1, veh_handler);
    if (!g_veh_handle) return FALSE;

    // İkinci handler: single-step (INT3 geri koyma)
    AddVectoredExceptionHandler(1, veh_single_step_handler);

    return TRUE;
}

BOOL veh_hook_install(PVOID target, VEH_CALLBACK callback, void *user_data)
{
    if (g_hook_count >= MAX_VEH_HOOKS) return FALSE;
    if (!g_veh_handle && !veh_hook_init()) return FALSE;

    VEH_HOOK_ENTRY *hook = &g_hooks[g_hook_count];
    hook->target_addr = target;
    hook->original_byte = *(BYTE *)target;
    hook->callback = callback;
    hook->user_data = user_data;
    hook->active = TRUE;

    // İlk byte'ı INT3 ile değiştir
    DWORD oldProt;
    VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    *(BYTE *)target = 0xCC;
    VirtualProtect(target, 1, oldProt, &oldProt);

    g_hook_count++;
    return TRUE;
}

BOOL veh_hook_remove(PVOID target)
{
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].target_addr == target && g_hooks[i].active) {
            DWORD oldProt;
            VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt);
            *(BYTE *)target = g_hooks[i].original_byte;
            VirtualProtect(target, 1, oldProt, &oldProt);

            g_hooks[i].active = FALSE;
            return TRUE;
        }
    }
    return FALSE;
}

void veh_hook_cleanup(void)
{
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].active) {
            veh_hook_remove(g_hooks[i].target_addr);
        }
    }

    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }

    g_hook_count = 0;
}

// =============================================================================
// Hardware Breakpoint Hook — 0 byte değişiklik
//
// DR0-DR3 debug register'larını kullanarak hook.
// Bellekte hiçbir byte değişmez — CRC check imkansız.
//
// Risk: XIGNCODE NtGetContextThread ile DR register'ları tarıyor
//       ama sadece %20 olasılıkla (10 oturumdan 2'sinde)
// =============================================================================

typedef struct {
    PVOID target;
    VEH_CALLBACK callback;
    void *user_data;
    int dr_index; // 0-3
    BOOL active;
} HWBP_ENTRY;

static HWBP_ENTRY g_hwbp[4] = {0};
static PVOID g_hwbp_veh = NULL;

static LONG CALLBACK hwbp_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID addr = ep->ExceptionRecord->ExceptionAddress;

    for (int i = 0; i < 4; i++) {
        if (!g_hwbp[i].active) continue;
        if (g_hwbp[i].target != addr) continue;

        // DR6'daki breakpoint hit flag'ini kontrol et
        DWORD dr6 = ep->ContextRecord->Dr6;
        if (!(dr6 & (1 << i))) continue;

        // Callback çağır
        if (g_hwbp[i].callback) {
            g_hwbp[i].callback(ep->ContextRecord, g_hwbp[i].user_data);
        }

        // DR6 temizle
        ep->ContextRecord->Dr6 = 0;

        // Breakpoint'i geçici olarak devre dışı bırak + single step
        // (sonsuz döngüyü önlemek için)
        ep->ContextRecord->Dr7 &= ~(3 << (i * 2)); // bu DR'yi devre dışı
        ep->ContextRecord->EFlags |= 0x100; // TF

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Single-step sonrası: breakpoint'i geri etkinleştir
    for (int i = 0; i < 4; i++) {
        if (!g_hwbp[i].active) continue;
        // DR7'de bu DR'nin L bit'i kapalıysa geri aç
        if (!(ep->ContextRecord->Dr7 & (1 << (i * 2)))) {
            ep->ContextRecord->Dr7 |= (1 << (i * 2));
            ep->ContextRecord->EFlags &= ~0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL hwbp_hook_install(PVOID target, VEH_CALLBACK callback, void *user_data)
{
    // Boş DR slot bul
    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (!g_hwbp[i].active) { slot = i; break; }
    }
    if (slot == -1) return FALSE;

    if (!g_hwbp_veh) {
        g_hwbp_veh = AddVectoredExceptionHandler(1, hwbp_handler);
        if (!g_hwbp_veh) return FALSE;
    }

    g_hwbp[slot].target = target;
    g_hwbp[slot].callback = callback;
    g_hwbp[slot].user_data = user_data;
    g_hwbp[slot].dr_index = slot;
    g_hwbp[slot].active = TRUE;

    // Mevcut thread'in debug register'larını ayarla
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    // DR[slot] = target address
    switch (slot) {
        case 0: ctx.Dr0 = (DWORD)(ULONG_PTR)target; break;
        case 1: ctx.Dr1 = (DWORD)(ULONG_PTR)target; break;
        case 2: ctx.Dr2 = (DWORD)(ULONG_PTR)target; break;
        case 3: ctx.Dr3 = (DWORD)(ULONG_PTR)target; break;
    }

    // DR7: Enable breakpoint (L[slot] = 1, condition = execution, len = 1 byte)
    ctx.Dr7 |= (1 << (slot * 2));        // L[slot] enable
    ctx.Dr7 &= ~(0xF << (16 + slot * 4)); // condition+len temizle
    // condition = 00 (execution), len = 00 (1 byte) — zaten 0

    ctx.Dr6 = 0;
    SetThreadContext(hThread, &ctx);

    return TRUE;
}

BOOL hwbp_hook_remove(PVOID target)
{
    for (int i = 0; i < 4; i++) {
        if (!g_hwbp[i].active || g_hwbp[i].target != target) continue;

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hThread = GetCurrentThread();
        GetThreadContext(hThread, &ctx);

        // DR7'den devre dışı bırak
        ctx.Dr7 &= ~(1 << (i * 2));

        // DR[i] temizle
        switch (i) {
            case 0: ctx.Dr0 = 0; break;
            case 1: ctx.Dr1 = 0; break;
            case 2: ctx.Dr2 = 0; break;
            case 3: ctx.Dr3 = 0; break;
        }

        SetThreadContext(hThread, &ctx);
        g_hwbp[i].active = FALSE;
        return TRUE;
    }
    return FALSE;
}
