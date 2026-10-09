#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <windows.h>
#include <stdio.h>

// ============================================================
// Knight Online Pointer & Offset Tablosu
// ============================================================

// --- Base Pointers ---
#define KO_PTR_CHR          0x01115574
#define KO_PTR_PKT          0x01115654
#define KO_PTR_DLG          0x0111563C
#define KO_PTR_RECV1        0x01115650
#define KO_SMMB             0x0111555C
#define KO_FLDB             0x01115580
#define KO_ITOB             0x01115544

// --- Function Addresses ---
#define KO_SND_FNC          0x007032E0
#define KO_RECV_FNC         0x0084C700
#define KO_FNSB             0x00503BE0
#define KO_FMBS             0x0050DF80

// --- Camera ---
#define KO_CAMERA_HOOK              0x007A904A
#define KO_CAMERA_DISTANCE_OFF      0x000001AC

// --- Character Offsets (KO_PTR_CHR uzerinden) ---
#define KO_OFF_ID           0x000006A0
#define KO_OFF_NAME         0x000006A4
#define KO_OFF_NATION       0x000006C4
#define KO_OFF_RACE         0x000006C0
#define KO_OFF_CLASS        0x000006CC
#define KO_OFF_LEVEL        0x000006D0
#define KO_OFF_MAXHP        0x000006D4
#define KO_OFF_HP           0x000006D8
#define KO_OFF_MAX_MP       0x00000BEC
#define KO_OFF_MP           0x00000BF0
#define KO_OFF_GOLD         0x00000BFC
#define KO_OFF_POSX         0x000003CC
#define KO_OFF_POSY         0x000003D4
#define KO_OFF_POSZ         0x00000194
#define KO_OFF_TARGET       0x00000660
#define KO_OFF_CHR_PTR      0x00000358

// --- Skill Offsets ---
#define SKILL_OFF_ID            0x00000010
#define SKILL_OFF_SELF_ANI      0x00000060
#define SKILL_OFF_CAST_TIME     0x000000A8
#define SKILL_OFF_COOLDOWN      0x000000AC
#define SKILL_OFF_SUCCESS_RATE  0x000000BC
#define SKILL_OFF_BLIND_SILENCE 0x000000C0
#define SKILL_OFF_RANGE         0x000000C8

// --- Scale Offsets ---
#define KO_SCALE_X_OFF      0x00000068
#define KO_SCALE_Y_OFF      0x0000006C
#define KO_SCALE_Z_OFF      0x00000070

// --- Magic / Area Skill ---
#define KO_AREA_SKILL_MOUSEMOVE_ADDR    0x00804990
#define KO_GAMEPROC_MAGIC_MGR_OFF       0x00000468
#define KO_MAGIC_REGION_STATE_OFF       0x000000D0
#define KO_MAGIC_REGION_SKILL_OFF       0x000000D4
#define KO_MAGIC_REGION_FX_ID_OFF       0x000001BC
#define KO_GAMEPROC_MOUSE_SKILL_POS_OFF 0x00000760
#define KO_FX_SET_BUNDLE_POS            0x008BBA40

// --- Game Proc ---
#define KO_PTR_GameProcIntro            0x0111562C
#define KO_PTR_CGameProcIntroChrSelect  0x01115640

// --- RVA Offsets ---
#define KO_SCALE_SET_RVA                    0x000E2B90
#define KO_CHARACTER_GET_BY_ID_RVA          0x0010DF80
#define KO_LOCAL_PLAYER_RVA                 0x00D15574
#define KO_PLAYER_MANAGER_RVA               0x00D15580
#define KO_DEATH_RENDER_TICKJOINTS_CALL_RVA 0x0024052E
#define KO_DEATH_TICK_JOINTS_RVA            0x00242760
#define KO_NPC_VTABLE_RVA                   0x00C1E3D4
#define KO_FPS_SECPERFRAME_RVA              0x00D8B5E0

// --- Constants ---
#define KO_RACE_NPC         100

// ============================================================
// Module API
// ============================================================

// --- Log sistemi ---
void log_init(const char *path);
void log_close(void);
void log_write(const char *category, const char *fmt, ...);

// --- Syscall ---
typedef struct {
    DWORD NtProtectVirtualMemory;
    DWORD NtQueryVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtOpenProcess;
    DWORD NtQuerySystemInformation;
    DWORD NtQueryInformationProcess;
    DWORD NtAllocateVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtClose;
} SYSCALL_TABLE;

extern SYSCALL_TABLE g_sc;
BOOL syscall_init(void);

// --- Anti-Signature ---
BOOL antisig_wipe_header(PVOID base);
BOOL antisig_morph_prologues(PVOID base);

// --- Stealth (PEB unlink + PE wipe + file rename + section remap) ---
void stealth_hide(HMODULE hMod);
void stealth_restore(void);
const char *stealth_get_orig_path(void);
const char *stealth_get_moved_path(void);

// --- XIGNCODE Monitor ---
void xmon_start(void);
void xmon_stop(void);

// --- Packet Capture ---
BOOL pcap_start(void);
void pcap_stop(void);

// --- Game State Reader ---
void gstate_start(void);
void gstate_stop(void);
void gstate_dump_once(void);

// --- Payload entry (d3d9 proxy icinden cagirilir) ---
void payload_startup(HMODULE selfModule);
void payload_shutdown(void);

#endif
