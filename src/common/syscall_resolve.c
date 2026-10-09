#include "syscall_defs.h"
#include <stdio.h>

SYSCALL_TABLE g_syscalls = {0};

// ntdll Nt* fonksiyonlarının syscall numarasını çıkart.
// Windows x86'da her Nt fonksiyonu şu pattern ile başlar:
//   B8 xx xx xx xx    mov eax, <syscall_number>
//   BA xx xx xx xx    mov edx, <wow64_transition> (Win10) veya
//   33 C9             xor ecx, ecx (Win7)
// İlk instruction'daki immediate değer syscall numarasıdır.
static DWORD extract_syscall_number(PVOID func_addr)
{
    BYTE *code = (BYTE *)func_addr;

    // Pattern 1: B8 xx xx xx xx (mov eax, imm32) - en yaygın
    if (code[0] == 0xB8) {
        return *(DWORD *)(code + 1);
    }

    // Pattern 2: 4C 8B D1 B8 xx xx xx xx (x64: mov r10, rcx; mov eax, imm32)
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8) {
        return *(DWORD *)(code + 4);
    }

    // Hook'lanmış olabilir - disk kopyasından çözmemiz gerekecek
    return 0xFFFFFFFF;
}

// ntdll'in disk üzerindeki temiz kopyasından syscall numaralarını çöz.
// XIGNCODE ntdll'i hook'lamış olsa bile, disk kopyası orijinal.
static DWORD extract_from_disk_copy(const char *func_name)
{
    // ntdll'in disk kopyasını oku
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return 0xFFFFFFFF;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *fileBuf = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (!fileBuf) { CloseHandle(hFile); return 0xFFFFFFFF; }

    DWORD bytesRead;
    ReadFile(hFile, fileBuf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // PE header parse
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fileBuf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(fileBuf + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exports = NULL;

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // RVA -> file offset dönüşümü
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (exportRVA >= sections[i].VirtualAddress &&
            exportRVA < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            DWORD offset = exportRVA - sections[i].VirtualAddress + sections[i].PointerToRawData;
            exports = (IMAGE_EXPORT_DIRECTORY *)(fileBuf + offset);
            break;
        }
    }

    if (!exports) { VirtualFree(fileBuf, 0, MEM_RELEASE); return 0xFFFFFFFF; }

    // Export tablosundan fonksiyonu bul
    // RVA'ları file offset'e çevirmek için helper
    #define RVA_TO_OFFSET(rva) ({ \
        DWORD _off = 0; \
        for (WORD _i = 0; _i < nt->FileHeader.NumberOfSections; _i++) { \
            if ((rva) >= sections[_i].VirtualAddress && \
                (rva) < sections[_i].VirtualAddress + sections[_i].Misc.VirtualSize) { \
                _off = (rva) - sections[_i].VirtualAddress + sections[_i].PointerToRawData; \
                break; \
            } \
        } \
        _off; \
    })

    DWORD *nameRVAs = (DWORD *)(fileBuf + RVA_TO_OFFSET(exports->AddressOfNames));
    WORD *ordinals = (WORD *)(fileBuf + RVA_TO_OFFSET(exports->AddressOfNameOrdinals));
    DWORD *funcRVAs = (DWORD *)(fileBuf + RVA_TO_OFFSET(exports->AddressOfFunctions));

    DWORD result = 0xFFFFFFFF;

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *)(fileBuf + RVA_TO_OFFSET(nameRVAs[i]));
        if (strcmp(name, func_name) == 0) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            DWORD funcOffset = RVA_TO_OFFSET(funcRVA);
            result = extract_syscall_number(fileBuf + funcOffset);
            break;
        }
    }

    #undef RVA_TO_OFFSET
    VirtualFree(fileBuf, 0, MEM_RELEASE);
    return result;
}

// Önce bellekteki ntdll'den dene, hook'lanmışsa disk kopyasından çöz
static DWORD resolve_one(const char *func_name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0xFFFFFFFF;

    PVOID func = (PVOID)GetProcAddress(ntdll, func_name);
    if (!func) return 0xFFFFFFFF;

    DWORD num = extract_syscall_number(func);
    if (num == 0xFFFFFFFF) {
        // Bellekteki kopya hook'lanmış, disk kopyasından çöz
        num = extract_from_disk_copy(func_name);
    }
    return num;
}

BOOL resolve_syscall_numbers(void)
{
    struct { DWORD *slot; const char *name; } entries[] = {
        { &g_syscalls.NtProtectVirtualMemory,    "NtProtectVirtualMemory" },
        { &g_syscalls.NtQueryVirtualMemory,      "NtQueryVirtualMemory" },
        { &g_syscalls.NtReadVirtualMemory,       "NtReadVirtualMemory" },
        { &g_syscalls.NtWriteVirtualMemory,      "NtWriteVirtualMemory" },
        { &g_syscalls.NtOpenProcess,             "NtOpenProcess" },
        { &g_syscalls.NtQuerySystemInformation,  "NtQuerySystemInformation" },
        { &g_syscalls.NtQueryInformationProcess, "NtQueryInformationProcess" },
        { &g_syscalls.NtSetInformationThread,    "NtSetInformationThread" },
        { &g_syscalls.NtGetContextThread,        "NtGetContextThread" },
        { &g_syscalls.NtSetContextThread,        "NtSetContextThread" },
        { &g_syscalls.NtCreateThreadEx,          "NtCreateThreadEx" },
        { &g_syscalls.NtAllocateVirtualMemory,   "NtAllocateVirtualMemory" },
        { &g_syscalls.NtFreeVirtualMemory,       "NtFreeVirtualMemory" },
        { &g_syscalls.NtClose,                   "NtClose" },
        { &g_syscalls.NtMapViewOfSection,        "NtMapViewOfSection" },
        { &g_syscalls.NtUnmapViewOfSection,      "NtUnmapViewOfSection" },
    };

    BOOL success = TRUE;
    for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        *entries[i].slot = resolve_one(entries[i].name);
        if (*entries[i].slot == 0xFFFFFFFF) {
            success = FALSE;
        }
    }
    return success;
}
