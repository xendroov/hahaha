#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include <windows.h>
#include <winternl.h>

// --- Syscall numaraları Windows build'ine göre değişir ---
// Runtime'da ntdll'den dinamik olarak çözülür (resolve_syscall_numbers)
typedef struct {
    DWORD NtProtectVirtualMemory;
    DWORD NtQueryVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtOpenProcess;
    DWORD NtQuerySystemInformation;
    DWORD NtQueryInformationProcess;
    DWORD NtSetInformationThread;
    DWORD NtGetContextThread;
    DWORD NtSetContextThread;
    DWORD NtCreateThreadEx;
    DWORD NtAllocateVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtClose;
    DWORD NtMapViewOfSection;
    DWORD NtUnmapViewOfSection;
} SYSCALL_TABLE;

extern SYSCALL_TABLE g_syscalls;

// --- NT yapıları (winternl.h'da eksik olanlar) ---
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;

#ifndef THREAD_INFORMATION_CLASS_DEFINED
typedef enum _THREAD_INFO_CLASS {
    ThreadHideFromDebugger = 0x11
} THREAD_INFO_CLASS;
#endif

// --- Fonksiyon prototipleri ---

// Syscall numaralarını ntdll'den çöz (hook'lanmamış disk kopyasından)
BOOL resolve_syscall_numbers(void);

// Direct syscall wrapper'ları (ntdll'e dokunmaz)
NTSTATUS dc_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS dc_NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemInfoClass,
    PVOID MemInfo,
    SIZE_T MemInfoLength,
    PSIZE_T ReturnLength
);

NTSTATUS dc_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    PSIZE_T BytesRead
);

NTSTATUS dc_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T Size,
    PSIZE_T BytesWritten
);

NTSTATUS dc_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS dc_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

NTSTATUS dc_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInfoClass,
    PVOID ProcessInfo,
    ULONG ProcessInfoLength,
    PULONG ReturnLength
);

NTSTATUS dc_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    void *ClientId // CLIENT_ID*
);

NTSTATUS dc_NtClose(HANDLE Handle);

#endif // SYSCALL_DEFS_H
