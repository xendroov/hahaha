#include "syscall_defs.h"
#include <string.h>

// Runtime'da executable memory'ye syscall stub yazan versiyon.
// MASM/NASM yoksa bu kullanılır — aynı işi yapar.
//
// Her stub şu makine kodunu üretir (WoW64, x86):
//   B8 xx xx xx xx     mov eax, <syscall_number>
//   FF 15 yy yy yy yy  call dword ptr [wow64_transition]  ; fs:[0xC0]'dan alınan adres
//   C3                  ret
//
// Toplam: 12 byte per stub

#define STUB_SIZE 12
#define MAX_STUBS 16

typedef NTSTATUS (NTAPI *fn_generic)();

static BYTE *g_stub_memory = NULL;
static fn_generic g_stub_funcs[MAX_STUBS] = {0};

// fs:[0xC0] adresini oku — WoW64 syscall geçiş fonksiyonu
static DWORD get_wow64_transition(void)
{
    DWORD addr = 0;
    __asm {
        mov eax, dword ptr fs:[0C0h]
        mov addr, eax
    }
    return addr;
}

// Tek bir syscall stub üret
static fn_generic build_stub(BYTE *dest, DWORD syscall_num)
{
    DWORD wow64 = get_wow64_transition();

    if (wow64 != 0) {
        // WoW64 path
        dest[0] = 0xB8;                                    // mov eax, imm32
        *(DWORD *)(dest + 1) = syscall_num;
        dest[5] = 0xBA;                                    // mov edx, imm32
        *(DWORD *)(dest + 6) = wow64;                      // wow64 transition addr
        dest[10] = 0xFF; dest[11] = 0xD2;                  // call edx
        // ret — caller'ın stdcall ret'i kullanılır
    } else {
        // Native x86 (nadir)
        dest[0] = 0xB8;                                    // mov eax, imm32
        *(DWORD *)(dest + 1) = syscall_num;
        dest[5] = 0xCD; dest[6] = 0x2E;                    // int 2Eh
        dest[7] = 0xC3;                                    // ret
    }

    return (fn_generic)dest;
}

// Tüm syscall stub'larını hazırla
BOOL build_all_syscall_stubs(void)
{
    if (!resolve_syscall_numbers()) return FALSE;

    // Executable memory tahsis et
    SIZE_T total = STUB_SIZE * MAX_STUBS;
    g_stub_memory = (BYTE *)VirtualAlloc(
        NULL, total,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!g_stub_memory) return FALSE;

    DWORD *nums = (DWORD *)&g_syscalls;
    for (int i = 0; i < MAX_STUBS; i++) {
        if (nums[i] == 0 || nums[i] == 0xFFFFFFFF) continue;
        g_stub_funcs[i] = build_stub(g_stub_memory + (i * STUB_SIZE), nums[i]);
    }

    // RWX -> RX (XIGNCODE RWX sayfalarını tarayabilir)
    DWORD old;
    VirtualProtect(g_stub_memory, total, PAGE_EXECUTE_READ, &old);

    return TRUE;
}

void cleanup_syscall_stubs(void)
{
    if (g_stub_memory) {
        VirtualFree(g_stub_memory, 0, MEM_RELEASE);
        g_stub_memory = NULL;
    }
    memset(g_stub_funcs, 0, sizeof(g_stub_funcs));
}

// --- Type-safe wrapper'lar ---
// Stub index'leri SYSCALL_TABLE struct member sırasıyla eşleşir

NTSTATUS dc_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    return ((fn)g_stub_funcs[0])(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS dc_NtQueryVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemInfoClass,
    PVOID MemInfo, SIZE_T MemInfoLength, PSIZE_T ReturnLength)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
    return ((fn)g_stub_funcs[1])(ProcessHandle, BaseAddress, MemInfoClass, MemInfo, MemInfoLength, ReturnLength);
}

NTSTATUS dc_NtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return ((fn)g_stub_funcs[2])(ProcessHandle, BaseAddress, Buffer, Size, BytesRead);
}

NTSTATUS dc_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return ((fn)g_stub_funcs[3])(ProcessHandle, BaseAddress, Buffer, Size, BytesWritten);
}

NTSTATUS dc_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    return ((fn)g_stub_funcs[11])(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS dc_NtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PVOID*, PSIZE_T, ULONG);
    return ((fn)g_stub_funcs[12])(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS dc_NtQueryInformationProcess(
    HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInfoClass,
    PVOID ProcessInfo, ULONG ProcessInfoLength, PULONG ReturnLength)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    return ((fn)g_stub_funcs[6])(ProcessHandle, ProcessInfoClass, ProcessInfo, ProcessInfoLength, ReturnLength);
}

NTSTATUS dc_NtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, void *ClientId)
{
    typedef NTSTATUS (NTAPI *fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, void*);
    return ((fn)g_stub_funcs[4])(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS dc_NtClose(HANDLE Handle)
{
    typedef NTSTATUS (NTAPI *fn)(HANDLE);
    return ((fn)g_stub_funcs[13])(Handle);
}
