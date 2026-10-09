; =============================================================================
; Direct Syscall Stub — x86 (WoW64 ortam, Windows 10/11)
;
; ntdll'in inline hook'lanmasına gerek kalmadan doğrudan kernel'a gider.
; XIGNCODE ntdll .text section'ını istediği kadar kontrol etsin —
; biz ntdll'e hiç dokunmuyoruz.
;
; Windows x86 syscall mekanizması:
;   EAX = syscall numarası
;   EDX = parametre stack pointer'ı
;   SYSENTER (veya INT 2E) ile kernel'a geçiş
;
; WoW64 (32-bit process on 64-bit Windows):
;   ntdll!Wow64SystemServiceCall -> fs:[0xC0] (wow64cpu!KiFastSystemCall)
;   Bu, 32-bit parametreleri 64-bit'e çevirip syscall yapar.
; =============================================================================

.686
.model flat, stdcall
.code

EXTERN g_syscalls:DWORD  ; SYSCALL_TABLE yapısı

; --- Wow64 geçiş adresi ---
; fs:[0xC0] = wow64cpu!KiFastSystemCall (WoW64 ortamda)
; Native 32-bit'te: ntdll!KiFastSystemCall (SYSENTER)

; Makro: Direct syscall çağrısı
; offset = g_syscalls yapısındaki DWORD offset
do_syscall MACRO offset
    mov eax, DWORD PTR [g_syscalls + offset]
    mov edx, esp
    add edx, 4          ; ilk parametre (return address'i atla)

    ; WoW64 kontrolü: fs:[0xC0] varsa WoW64, yoksa native
    push ecx
    mov ecx, DWORD PTR fs:[0C0h]
    test ecx, ecx
    pop ecx
    jz short _native

    ; WoW64 path: wow64cpu!KiFastSystemCall üzerinden
    call DWORD PTR fs:[0C0h]
    ret

_native:
    ; Native x86 path: doğrudan SYSENTER
    ; (Windows 10 x86 native — çok nadir)
    int 2Eh
    ret
ENDM


; =============================================================================
; Exported syscall wrapper fonksiyonları
; Her biri stdcall convention ile çağrılır.
; =============================================================================

; NTSTATUS dc_NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)
dc_NtProtectVirtualMemory PROC
    do_syscall 0   ; offset 0 = ilk DWORD
dc_NtProtectVirtualMemory ENDP

; NTSTATUS dc_NtQueryVirtualMemory(HANDLE, PVOID, class, PVOID, SIZE_T, PSIZE_T)
dc_NtQueryVirtualMemory PROC
    do_syscall 4
dc_NtQueryVirtualMemory ENDP

; NTSTATUS dc_NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
dc_NtReadVirtualMemory PROC
    do_syscall 8
dc_NtReadVirtualMemory ENDP

; NTSTATUS dc_NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
dc_NtWriteVirtualMemory PROC
    do_syscall 12
dc_NtWriteVirtualMemory ENDP

; NTSTATUS dc_NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
dc_NtOpenProcess PROC
    do_syscall 16
dc_NtOpenProcess ENDP

; NTSTATUS dc_NtQuerySystemInformation(class, PVOID, ULONG, PULONG)
dc_NtQuerySystemInformation PROC
    do_syscall 20
dc_NtQuerySystemInformation ENDP

; NTSTATUS dc_NtQueryInformationProcess(HANDLE, class, PVOID, ULONG, PULONG)
dc_NtQueryInformationProcess PROC
    do_syscall 24
dc_NtQueryInformationProcess ENDP

; NTSTATUS dc_NtSetInformationThread(HANDLE, class, PVOID, ULONG)
dc_NtSetInformationThread PROC
    do_syscall 28
dc_NtSetInformationThread ENDP

; NTSTATUS dc_NtGetContextThread(HANDLE, PCONTEXT)
dc_NtGetContextThread PROC
    do_syscall 32
dc_NtGetContextThread ENDP

; NTSTATUS dc_NtSetContextThread(HANDLE, PCONTEXT)
dc_NtSetContextThread PROC
    do_syscall 36
dc_NtSetContextThread ENDP

; NTSTATUS dc_NtCreateThreadEx(...)
dc_NtCreateThreadEx PROC
    do_syscall 40
dc_NtCreateThreadEx ENDP

; NTSTATUS dc_NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)
dc_NtAllocateVirtualMemory PROC
    do_syscall 44
dc_NtAllocateVirtualMemory ENDP

; NTSTATUS dc_NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG)
dc_NtFreeVirtualMemory PROC
    do_syscall 48
dc_NtFreeVirtualMemory ENDP

; NTSTATUS dc_NtClose(HANDLE)
dc_NtClose PROC
    do_syscall 52
dc_NtClose ENDP

; NTSTATUS dc_NtMapViewOfSection(...)
dc_NtMapViewOfSection PROC
    do_syscall 56
dc_NtMapViewOfSection ENDP

; NTSTATUS dc_NtUnmapViewOfSection(HANDLE, PVOID)
dc_NtUnmapViewOfSection PROC
    do_syscall 60
dc_NtUnmapViewOfSection ENDP

END
