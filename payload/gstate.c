// Game State Reader — Knight Online bellek okuyucu
//
// Periyodik olarak oyun durumunu loglar:
//   - Karakter pozisyonu (X, Y, Z)
//   - HP / Max HP / MP / Max MP
//   - Hedef bilgisi
//   - Zone / Map ID
//
// Adresler: KnightOnLine.exe'nin sabit base'ine gore.
// Guncellemeler icin gstate_set_offsets() kullanilabilir.

#include "payload.h"
#include <string.h>

static volatile BOOL g_gstate_running = FALSE;
static HANDLE g_gstate_thread = NULL;

// Known base pointers (KnightOnLine.exe static addresses)
// These are starting points — actual values read through pointer chains
typedef struct {
    DWORD pPlayerBase;    // Player info base pointer
    DWORD oPositionX;     // Offset: float X
    DWORD oPositionY;     // Offset: float Y
    DWORD oPositionZ;     // Offset: float Z
    DWORD oHP;            // Offset: current HP
    DWORD oMaxHP;         // Offset: max HP
    DWORD oMP;            // Offset: current MP
    DWORD oMaxMP;         // Offset: max MP
    DWORD oLevel;         // Offset: level
    DWORD oName;          // Offset: character name string
    DWORD oZoneID;        // Offset: zone/map ID
    DWORD oTargetID;      // Offset: current target ID
    DWORD pSocketBase;    // CAPISocket instance pointer
    DWORD oEncryptFlag;   // Encryption enabled flag
} GAME_OFFSETS;

static GAME_OFFSETS g_offsets = {
    .pPlayerBase  = 0x0110D6A0,
    .oPositionX   = 0x08,
    .oPositionY   = 0x10,
    .oPositionZ   = 0x0C,
    .oHP          = 0x28,
    .oMaxHP       = 0x2C,
    .oMP          = 0x30,
    .oMaxMP       = 0x34,
    .oLevel       = 0x24,
    .oName        = 0x60,
    .oZoneID      = 0x04,
    .oTargetID    = 0x48,
    .pSocketBase  = 0x01115A38,
    .oEncryptFlag = 0x011159B4,
};

void gstate_set_offsets(GAME_OFFSETS *offsets)
{
    memcpy(&g_offsets, offsets, sizeof(GAME_OFFSETS));
}

static BOOL safe_read(DWORD addr, void *out, SIZE_T size)
{
    __try {
        memcpy(out, (void *)addr, size);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static DWORD deref(DWORD ptr)
{
    DWORD val = 0;
    if (!safe_read(ptr, &val, 4)) return 0;
    return val;
}

static float deref_float(DWORD ptr)
{
    float val = 0.0f;
    safe_read(ptr, &val, 4);
    return val;
}

void gstate_dump_once(void)
{
    DWORD playerBase = deref(g_offsets.pPlayerBase);
    if (!playerBase) {
        log_write("GSTATE", "Player base NULL — oyun yuklenmemis olabilir");
        return;
    }

    float x = deref_float(playerBase + g_offsets.oPositionX);
    float y = deref_float(playerBase + g_offsets.oPositionY);
    float z = deref_float(playerBase + g_offsets.oPositionZ);

    DWORD hp    = deref(playerBase + g_offsets.oHP);
    DWORD maxhp = deref(playerBase + g_offsets.oMaxHP);
    DWORD mp    = deref(playerBase + g_offsets.oMP);
    DWORD maxmp = deref(playerBase + g_offsets.oMaxMP);
    DWORD level = deref(playerBase + g_offsets.oLevel);
    DWORD zone  = deref(playerBase + g_offsets.oZoneID);
    DWORD target = deref(playerBase + g_offsets.oTargetID);

    char name[32] = {0};
    safe_read(playerBase + g_offsets.oName, name, sizeof(name) - 1);

    DWORD encFlag = deref(g_offsets.oEncryptFlag);

    log_write("GSTATE", "Player: %s Lv%u Zone=%u", name, level, zone);
    log_write("GSTATE", "  Pos: %.1f, %.1f, %.1f", x, y, z);
    log_write("GSTATE", "  HP: %u/%u  MP: %u/%u", hp, maxhp, mp, maxmp);
    log_write("GSTATE", "  Target: %u  Encrypt: %u", target, encFlag);
}

static DWORD WINAPI gstate_thread(LPVOID param)
{
    int cycle = 0;

    while (g_gstate_running) {
        cycle++;
        if (cycle % 10 == 1) // her 10 saniyede detayli log
            log_write("GSTATE", "--- Cycle %d ---", cycle);

        gstate_dump_once();

        // 1 saniyede bir oku
        for (int i = 0; i < 10 && g_gstate_running; i++)
            Sleep(100);
    }

    log_write("GSTATE", "Reader durduruldu");
    return 0;
}

void gstate_start(void)
{
    if (g_gstate_running) return;
    g_gstate_running = TRUE;
    g_gstate_thread = CreateThread(NULL, 0, gstate_thread, NULL, 0, NULL);
    log_write("GSTATE", "Game state reader baslatildi (player base @ 0x%08X)",
              g_offsets.pPlayerBase);
}

void gstate_stop(void)
{
    g_gstate_running = FALSE;
    if (g_gstate_thread) {
        WaitForSingleObject(g_gstate_thread, 3000);
        CloseHandle(g_gstate_thread);
        g_gstate_thread = NULL;
    }
}
