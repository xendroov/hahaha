#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <windows.h>
#include <stdio.h>

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

#endif
