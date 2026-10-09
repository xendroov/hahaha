// Direct Syscall — ntdll'e dokunmadan kernel'a git
//
// XIGNCODE x3.xem ntdll .text'teki 12 fonksiyonu kontrol ediyor.
// Biz ntdll'i hiç yamamıyoruz — disk kopyasından syscall numarasını
// okuyup, kendi stub'ımızdan doğrudan kernel'a gidiyoruz.

#include "payload.h"
#include <string.h>

SYSCALL_TABLE g_sc = {0};

// ntdll fonksiyonunun ilk byte'larından syscall numarasını çıkart
// Windows x86: B8 xx xx xx xx (mov eax, syscall_num)
static DWORD extract_number(BYTE *func)
{
    if (func[0] == 0xB8)
        return *(DWORD *)(func + 1);

    // Hook'lanmış — E9 (JMP) veya başka bir şey
    return 0xFFFFFFFF;
}

static DWORD rva2offset(DWORD rva, IMAGE_SECTION_HEADER *sec, WORD nSec)
{
    WORD i;
    for (i = 0; i < nSec; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
    }
    return 0;
}

static DWORD resolve_from_disk(const char *funcName)
{
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(hFile); return 0xFFFFFFFF; }

    DWORD bytesRead;
    ReadFile(hFile, buf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD nSec = nt->FileHeader.NumberOfSections;

    DWORD expRVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY *expDir = (IMAGE_EXPORT_DIRECTORY *)(buf + rva2offset(expRVA, sec, nSec));

    DWORD *names = (DWORD *)(buf + rva2offset(expDir->AddressOfNames, sec, nSec));
    WORD *ords = (WORD *)(buf + rva2offset(expDir->AddressOfNameOrdinals, sec, nSec));
    DWORD *funcs = (DWORD *)(buf + rva2offset(expDir->AddressOfFunctions, sec, nSec));

    DWORD result = 0xFFFFFFFF;
    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char *name = (char *)(buf + rva2offset(names[i], sec, nSec));
        if (strcmp(name, funcName) == 0) {
            DWORD funcOffset = rva2offset(funcs[ords[i]], sec, nSec);
            result = extract_number(buf + funcOffset);
            break;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return result;
}

// Bellekteki ntdll'den dene, yoksa diskten
static DWORD resolve_one(const char *funcName)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0xFFFFFFFF;

    BYTE *func = (BYTE *)GetProcAddress(ntdll, funcName);
    if (!func) return 0xFFFFFFFF;

    DWORD num = extract_number(func);
    if (num == 0xFFFFFFFF)
        num = resolve_from_disk(funcName);

    return num;
}

BOOL syscall_init(void)
{
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
        *tbl[i].slot = resolve_one(tbl[i].name);
        if (*tbl[i].slot == 0xFFFFFFFF) ok = FALSE;
    }
    return ok;
}
