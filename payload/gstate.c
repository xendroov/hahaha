// Game State Reader — Knight Online bellek okuyucu
//
// KO_PTR_CHR (0x01115574) uzerinden pointer chain:
//   [KO_PTR_CHR] -> player struct base
//   + KO_OFF_* -> her alan
//
// 1 saniye periyotla loglar.

#include "payload.h"
#include <string.h>

static volatile BOOL g_gstate_running = FALSE;
static HANDLE g_gstate_thread = NULL;

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
    DWORD playerBase = deref(KO_PTR_CHR);
    if (!playerBase) {
        log_write("GSTATE", "Player base NULL — karakter secilmemis");
        return;
    }

    // Kimlik
    DWORD id    = deref(playerBase + KO_OFF_ID);
    DWORD cls   = deref(playerBase + KO_OFF_CLASS);
    DWORD level = deref(playerBase + KO_OFF_LEVEL);
    DWORD nation = deref(playerBase + KO_OFF_NATION);
    DWORD race  = deref(playerBase + KO_OFF_RACE);

    char name[32] = {0};
    safe_read(playerBase + KO_OFF_NAME, name, sizeof(name) - 1);

    // Saglık
    DWORD hp    = deref(playerBase + KO_OFF_HP);
    DWORD maxhp = deref(playerBase + KO_OFF_MAXHP);
    DWORD mp    = deref(playerBase + KO_OFF_MP);
    DWORD maxmp = deref(playerBase + KO_OFF_MAX_MP);
    DWORD gold  = deref(playerBase + KO_OFF_GOLD);

    // Pozisyon
    float posX = deref_float(playerBase + KO_OFF_POSX);
    float posY = deref_float(playerBase + KO_OFF_POSY);
    float posZ = deref_float(playerBase + KO_OFF_POSZ);

    // Hedef
    DWORD target = deref(playerBase + KO_OFF_TARGET);

    // Kamera mesafesi
    float camDist = 0.0f;
    DWORD camBase = deref(KO_CAMERA_HOOK);
    if (camBase)
        camDist = deref_float(camBase + KO_CAMERA_DISTANCE_OFF);

    log_write("GSTATE", "%s [ID:%u] Lv%u Class:%u Nation:%u Race:%u",
              name, id, level, cls, nation, race);
    log_write("GSTATE", "  HP: %u/%u  MP: %u/%u  Gold: %u",
              hp, maxhp, mp, maxmp, gold);
    log_write("GSTATE", "  Pos: %.1f, %.1f, %.1f  Target: %u",
              posX, posY, posZ, target);

    // Packet socket durumu
    DWORD pktBase = deref(KO_PTR_PKT);
    log_write("GSTATE", "  Socket: 0x%08X  CamDist: %.1f", pktBase, camDist);
}

static DWORD WINAPI gstate_thread(LPVOID param)
{
    int cycle = 0;

    while (g_gstate_running) {
        cycle++;
        if (cycle % 10 == 1)
            log_write("GSTATE", "--- Cycle %d ---", cycle);

        gstate_dump_once();

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
    log_write("GSTATE", "Game state reader baslatildi (CHR=0x%08X)", KO_PTR_CHR);
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
