#ifndef VEH_HOOK_H
#define VEH_HOOK_H

#include <windows.h>

// VEH (Vectored Exception Handler) Hook
//
// Inline hook alternatifi. Fonksiyonun ilk byte'ını INT3 (0xCC) ile
// değiştirip, VEH handler'da exception'ı yakalayarak detour'a yönlendirme.
//
// Avantajlar:
//   - Sadece 1 byte değişiklik (E9 JMP = 5 byte)
//   - XIGNCODE'un 5-byte JMP pattern araması bunu kaçırabilir
//   - Hook kaldırmak = 1 byte geri yazmak
//
// Dezavantajlar:
//   - Exception handling overhead (her çağrıda)
//   - XIGNCODE INT3 (0xCC) pattern'i de arayabilir
//   - Tek seferde en fazla ~4 hook (DR0-DR3 ile 0 byte değişiklik mümkün)
//
// Kullanım senaryosu:
//   CAPISocket::Send (0x704070) hook'u — paket capture/inject

#define MAX_VEH_HOOKS 16

typedef void (*VEH_CALLBACK)(PCONTEXT ctx, void *user_data);

typedef struct {
    PVOID target_addr;      // Hook'lanan fonksiyon adresi
    BYTE original_byte;     // Orijinal ilk byte (geri yüklemek için)
    VEH_CALLBACK callback;  // Detour fonksiyonu
    void *user_data;        // Callback'e geçirilecek veri
    BOOL active;
} VEH_HOOK_ENTRY;

// VEH hook sistemini başlat
BOOL veh_hook_init(void);

// Hook kur (fonksiyon girişindeki 1 byte'ı 0xCC ile değiştirir)
BOOL veh_hook_install(PVOID target, VEH_CALLBACK callback, void *user_data);

// Tek bir hook'u kaldır
BOOL veh_hook_remove(PVOID target);

// Tüm hook'ları kaldır ve sistemi temizle
void veh_hook_cleanup(void);

// --- Hardware Breakpoint Hook (0 byte değişiklik) ---
// DR0-DR3 register'larını kullanarak hook. Hiçbir byte değişmez.
// Risk: XIGNCODE NtGetContextThread ile DR register'ları tarıyor (%20 olasılık)

BOOL hwbp_hook_install(PVOID target, VEH_CALLBACK callback, void *user_data);
BOOL hwbp_hook_remove(PVOID target);

#endif // VEH_HOOK_H
