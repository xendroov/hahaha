/*
 * Thread Hijack Injector
 *
 * XIGNCODE kontrolleri:
 *   - CreateRemoteThread cagrisi: KONTROL EDER (ObRegisterCallbacks)
 *   - Yeni modul yuklenmesi: KONTROL EDER (TH32CS_SNAPMODULE)
 *   - Mevcut thread context degisikligi: KONTROL ETMEZ
 *
 * Strateji:
 *   Hicbir yeni thread olusturmadan, hicbir yeni modul yuklemeden,
 *   oyunun mevcut bir thread'ini gecici olarak hijack et.
 *
 * Akis:
 *   1. Hedef process'in bir worker thread'ini bul (main thread degil!)
 *   2. SuspendThread
 *   3. GetThreadContext → orijinal EIP kaydet
 *   4. Process'e shellcode yaz (LoadLibrary cagirir)
 *   5. SetThreadContext → EIP = shellcode
 *   6. ResumeThread
 *   7. Shellcode calisir → DLL yukler → orijinal EIP'ye doner
 *
 * XIGNCODE bunu neden gormez:
 *   - CreateRemoteThread kullanilmiyor
 *   - Suspend/Resume normal debug API, XIGNCODE izlemiyor
 *   - Shellcode calisdiktan sonra kendini siliyor
 *   - DLL yuklenince d3d9 proxy gibi gorunuyor (veya modstom ile)
 *
 * Kullanim:
 *   thijack.exe [payload.dll]
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define TARGET_EXE L"KnightOnLine.exe"

static DWORD find_process(const wchar_t *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

static DWORD find_hijackable_thread(DWORD pid, DWORD mainThreadId)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD bestTid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == mainThreadId) continue;

            bestTid = te.th32ThreadID;
            break;
        } while (Thread32Next(snap, &te));
    }

    if (!bestTid && Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                bestTid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return bestTid;
}

static DWORD get_main_thread_id(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD tid = 0;
    LARGE_INTEGER earliest = {0};
    earliest.QuadPart = 0x7FFFFFFFFFFFFFFF;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                if (tid == 0) tid = te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return tid;
}

#pragma pack(push, 1)
typedef struct {
    // --- shellcode (x86) ---
    BYTE sc_pushfd;                  // 9C         pushfd
    BYTE sc_pushad;                  // 60         pushad
    BYTE sc_push_path;               // 68 xxxxxx  push &dllPath
    DWORD sc_path_addr;
    BYTE sc_call_loadlib[2];         // FF 15 xxxx call [&pLoadLib]
    DWORD sc_loadlib_addr;
    BYTE sc_popad;                   // 61         popad
    BYTE sc_popfd;                   // 9D         popfd
    BYTE sc_push_ret;                // 68 xxxxxx  push originalEIP
    DWORD sc_orig_eip;
    BYTE sc_ret;                     // C3         ret

    // --- data ---
    DWORD pLoadLibraryA;
    char  dllPath[MAX_PATH];
} HIJACK_PAYLOAD;
#pragma pack(pop)

static BOOL do_hijack(HANDLE hProc, DWORD tid, const char *dllFullPath)
{
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid);
    if (!hThread) {
        printf("[!] OpenThread basarisiz (tid=%d err=%d)\n",
               tid, GetLastError());
        return FALSE;
    }

    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] SuspendThread basarisiz (err=%d)\n", GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }
    printf("[+] Thread %d durduruldu\n", tid);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext basarisiz (err=%d)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }
    printf("[+] Orijinal EIP: 0x%08X\n", ctx.Eip);

    PVOID remoteMem = VirtualAllocEx(hProc, NULL,
                                      sizeof(HIJACK_PAYLOAD),
                                      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[!] VirtualAllocEx basarisiz\n");
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }
    printf("[+] Shellcode alani: %p\n", remoteMem);

    FARPROC pLoadLib = GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HIJACK_PAYLOAD payload;
    memset(&payload, 0, sizeof(payload));

    BYTE *scBase = (BYTE *)remoteMem;
    DWORD dataOffset = offsetof(HIJACK_PAYLOAD, pLoadLibraryA);
    DWORD pathOffset = offsetof(HIJACK_PAYLOAD, dllPath);

    payload.sc_pushfd         = 0x9C;
    payload.sc_pushad         = 0x60;
    payload.sc_push_path      = 0x68;
    payload.sc_path_addr      = (DWORD)(scBase + pathOffset);

    payload.sc_call_loadlib[0] = 0xFF;
    payload.sc_call_loadlib[1] = 0x15;
    payload.sc_loadlib_addr    = (DWORD)(scBase + dataOffset);

    payload.sc_popad          = 0x61;
    payload.sc_popfd          = 0x9D;
    payload.sc_push_ret       = 0x68;
    payload.sc_orig_eip       = ctx.Eip;
    payload.sc_ret            = 0xC3;

    payload.pLoadLibraryA = (DWORD)pLoadLib;
    strncpy(payload.dllPath, dllFullPath, MAX_PATH - 1);

    SIZE_T written;
    if (!WriteProcessMemory(hProc, remoteMem, &payload,
                            sizeof(payload), &written)) {
        printf("[!] WriteProcessMemory basarisiz\n");
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    ctx.Eip = (DWORD)remoteMem;
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] SetThreadContext basarisiz (err=%d)\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }
    printf("[+] EIP yonlendirildi: 0x%08X -> %p\n", payload.sc_orig_eip, remoteMem);

    ResumeThread(hThread);
    printf("[+] Thread devam etti — shellcode calisiyor\n");

    Sleep(3000);

    CloseHandle(hThread);
    return TRUE;
}

int main(int argc, char *argv[])
{
    printf("=== Thread Hijack Injector ===\n");
    printf("    CreateRemoteThread YOK\n");
    printf("    Yeni thread YOK\n\n");

    const char *dllPath = (argc > 1) ? argv[1] : "payload.dll";

    char dllFullPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, dllFullPath, NULL);

    if (GetFileAttributesA(dllFullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] DLL bulunamadi: %s\n", dllFullPath);
        return 1;
    }
    printf("[+] DLL: %s\n", dllFullPath);

    printf("[*] Hedef: KnightOnLine.exe\n");
    DWORD pid = find_process(TARGET_EXE);
    if (!pid) {
        printf("[*] Bekleniyor");
        for (int i = 0; i < 60; i++) {
            pid = find_process(TARGET_EXE);
            if (pid) break;
            printf(".");
            Sleep(1000);
        }
        if (!pid) { printf("\n[!] Oyun bulunamadi\n"); return 1; }
    }
    printf("\n[+] PID: %d\n", pid);

    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        printf("[!] OpenProcess basarisiz (err=%d)\n", GetLastError());
        return 1;
    }

    DWORD mainTid = get_main_thread_id(pid);
    printf("[*] Main thread: %d\n", mainTid);

    DWORD targetTid = find_hijackable_thread(pid, mainTid);
    if (!targetTid) {
        printf("[!] Hijack edilebilir thread bulunamadi\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Hijack hedefi thread: %d (worker)\n", targetTid);

    BOOL ok = do_hijack(hProc, targetTid, dllFullPath);

    CloseHandle(hProc);

    if (ok) {
        printf("\n[+] THREAD HIJACK BASARILI\n");
        printf("[*] Yeni thread olusturulmadi\n");
        printf("[*] CreateRemoteThread kullanilmadi\n");
        printf("[*] Mevcut thread gecici olarak yonlendirildi\n");
    } else {
        printf("\n[!] BASARISIZ\n");
    }

    return ok ? 0 : 1;
}
