// Anti-Signature — IF.SPIDER RawCodeInjectedB bypass
//
// Injection sonrası çalışır:
//   1. PE header silme (MZ/PE yok → modül olarak tanınamaz)
//   2. MSVC prologue dönüştürme (byte pattern kırılır)

#include "payload.h"
#include <string.h>

BOOL antisig_wipe_header(PVOID base)
{
    BYTE *b = (BYTE *)base;
    if (b[0] != 'M' || b[1] != 'Z') return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;

    DWORD old;
    if (!VirtualProtect(b, headerSize, PAGE_READWRITE, &old))
        return FALSE;

    // Rastgele veriyle doldur (sıfır bloğu da imza olabilir)
    DWORD tick = GetTickCount();
    for (DWORD i = 0; i < headerSize; i++) {
        tick = tick * 1103515245 + 12345;
        b[i] = (BYTE)(tick >> 16);
    }

    VirtualProtect(b, headerSize, PAGE_NOACCESS, &old);
    return TRUE;
}

// "push ebp; mov ebp, esp" (55 8B EC) → "push ebp; mov ebp, esp" (55 89 E5)
// Aynı semantik, farklı encoding. XIGNCODE'un pattern'i kırılır.
BOOL antisig_morph_prologues(PVOID base)
{
    BYTE *b = (BYTE *)base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    int count = 0;

    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE *code = b + sec[s].VirtualAddress;
        DWORD size = sec[s].Misc.VirtualSize;

        DWORD old;
        VirtualProtect(code, size, PAGE_EXECUTE_READWRITE, &old);

        for (DWORD i = 0; i + 3 <= size; i++) {
            // 55 8B EC → 55 89 E5
            if (code[i] == 0x55 && code[i+1] == 0x8B && code[i+2] == 0xEC) {
                code[i+1] = 0x89;
                code[i+2] = 0xE5;
                count++;
                i += 2;
            }
            // 8B FF (mov edi,edi hotpatch) → 87 C0 (xchg eax,eax)
            if (code[i] == 0x8B && code[i+1] == 0xFF) {
                code[i] = 0x87;
                code[i+1] = 0xC0;
                count++;
                i += 1;
            }
        }

        VirtualProtect(code, size, old, &old);
    }

    return count > 0;
}
