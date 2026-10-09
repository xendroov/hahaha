#include <windows.h>
#include <string.h>

/*
 * Multi-layer stealth:
 *   1) PEB unlink — remove from all three module lists
 *   2) PE header wipe — zero MZ/PE signatures in memory
 *   3) File rename — move DLL out of game directory on disk
 *      NTFS allows renaming a loaded DLL; the section mapping survives.
 *      If XIGNCODE scans the game directory for non-original files,
 *      removing our DLL from the listing defeats it.
 *   4) Section disconnection — remap pages as MEM_PRIVATE
 *      Defeats NtQueryVirtualMemory MemoryMappedFilenameInformation.
 */

static char g_origPath[MAX_PATH];
static char g_movedPath[MAX_PATH];

static void unlink_entry(LIST_ENTRY *e)
{
    e->Blink->Flink = e->Flink;
    e->Flink->Blink = e->Blink;
    e->Flink = e;
    e->Blink = e;
}

static BOOL try_rename(const char *src, const char *dst)
{
    if (MoveFileA(src, dst))
        return TRUE;

    HANDLE hf = CreateFileA(src, DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return FALSE;

    typedef struct {
        DWORD  flags;
        HANDLE rootDir;
        DWORD  fileNameLen;
        WCHAR  fileName[MAX_PATH];
    } FILE_RENAME_INFO_EX;

    FILE_RENAME_INFO_EX ri;
    memset(&ri, 0, sizeof(ri));
    ri.flags = 0;
    ri.rootDir = NULL;
    ri.fileNameLen = (DWORD)(strlen(dst) * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, dst, -1, ri.fileName, MAX_PATH);

    BOOL ok = SetFileInformationByHandle(hf, FileRenameInfo,
                                          &ri, sizeof(ri));
    CloseHandle(hf);
    return ok;
}

static void remap_private(HMODULE hMod)
{
    BYTE *base = (BYTE *)hMod;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = base + 0x1000;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.AllocationBase != base)
            break;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
            SIZE_T regionSz = mbi.RegionSize;
            BYTE *buf = (BYTE *)VirtualAlloc(NULL, regionSz,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
            if (buf) {
                memcpy(buf, addr, regionSz);

                DWORD oldProt;
                if (VirtualProtect(addr, regionSz, PAGE_READWRITE, &oldProt)) {
                    memcpy(addr, buf, regionSz);
                    VirtualProtect(addr, regionSz, oldProt, &oldProt);
                }
                VirtualFree(buf, 0, MEM_RELEASE);
            }
        }
        addr += mbi.RegionSize;
    }
}

void stealth_hide(HMODULE hMod)
{
    GetModuleFileNameA(hMod, g_origPath, MAX_PATH);

    DWORD pebAddr;
    __asm {
        mov eax, dword ptr fs:[0x30]
        mov pebAddr, eax
    }

    DWORD ldrAddr = *(DWORD *)(pebAddr + 0x0C);
    LIST_ENTRY *head = (LIST_ENTRY *)(ldrAddr + 0x0C);
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        PVOID dllBase = *(PVOID *)((BYTE *)cur + 0x18);

        if (dllBase == (PVOID)hMod) {
            LIST_ENTRY *memLinks  = (LIST_ENTRY *)((BYTE *)cur + 0x08);
            LIST_ENTRY *initLinks = (LIST_ENTRY *)((BYTE *)cur + 0x10);

            unlink_entry(cur);
            unlink_entry(memLinks);
            unlink_entry(initLinks);

            WORD nameLen = *(WORD *)((BYTE *)cur + 0x24);
            PVOID nameBuf = *(PVOID *)((BYTE *)cur + 0x28);
            if (nameBuf && nameLen)
                memset(nameBuf, 0, nameLen);

            WORD baseLen = *(WORD *)((BYTE *)cur + 0x2C);
            PVOID baseBuf = *(PVOID *)((BYTE *)cur + 0x30);
            if (baseBuf && baseLen)
                memset(baseBuf, 0, baseLen);

            break;
        }
        cur = cur->Flink;
    }

    DWORD old;
    if (VirtualProtect((PVOID)hMod, 0x1000, PAGE_READWRITE, &old)) {
        memset((PVOID)hMod, 0, 0x1000);
        VirtualProtect((PVOID)hMod, 0x1000, old, &old);
    }

    if (g_origPath[0]) {
        char tmpDir[MAX_PATH];
        GetTempPathA(MAX_PATH, tmpDir);
        DWORD tick = GetTickCount();
        snprintf(g_movedPath, MAX_PATH, "%s~df%x.tmp", tmpDir, tick);

        if (!try_rename(g_origPath, g_movedPath)) {
            char *sep = strrchr(g_origPath, '\\');
            if (sep) {
                size_t dirLen = (size_t)(sep - g_origPath + 1);
                memcpy(g_movedPath, g_origPath, dirLen);
                snprintf(g_movedPath + dirLen, MAX_PATH - dirLen,
                         "~df%x.tmp", tick);
                try_rename(g_origPath, g_movedPath);
            }
        }
    }

    remap_private(hMod);
}

const char *stealth_get_orig_path(void) { return g_origPath; }
const char *stealth_get_moved_path(void) { return g_movedPath; }

void stealth_restore(void)
{
    if (g_movedPath[0] && g_origPath[0])
        MoveFileA(g_movedPath, g_origPath);
}
