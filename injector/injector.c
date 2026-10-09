// Stealth Injector v3.0 — SetWindowsHookEx
//
// XIGNCODE ObRegisterCallbacks ile process handle haklarini kirpiyor.
// VirtualAllocEx / WriteProcessMemory / CreateRemoteThread hepsi ACCESS_DENIED.
//
// Cozum: SetWindowsHookEx kullan — isletim sistemi DLL'i hedef process'e
// kendisi yukler. Process handle'a ihtiyac yok.
//
// Akis:
//   1. KnightOnLine.exe PID + pencere thread'ini bul
//   2. payload.dll'i injector'a LoadLibrary ile yukle
//   3. HookProc export'unu bul
//   4. SetWindowsHookEx(WH_GETMESSAGE) ile hook kur
//   5. PostThreadMessage ile hook'u tetikle
//   6. DllMain hedef process'te calisir, payload baslar
//   7. Hook kaldir (DLL bellekte kalir, cunku kendini pin'ledi)

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// --- Process bulma ---

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

// --- PID'ye ait pencereyi bul ---

typedef struct {
    DWORD pid;
    HWND hwnd;
} FIND_WND_DATA;

static BOOL CALLBACK enum_wnd_proc(HWND hwnd, LPARAM lParam)
{
    FIND_WND_DATA *data = (FIND_WND_DATA *)lParam;
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == data->pid && IsWindowVisible(hwnd)) {
        data->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND find_window_by_pid(DWORD pid)
{
    FIND_WND_DATA data = { .pid = pid, .hwnd = NULL };
    EnumWindows(enum_wnd_proc, (LPARAM)&data);
    return data.hwnd;
}

// --- Yontem 1: SetWindowsHookEx ---

static BOOL inject_hook(DWORD pid, const char *dllFullPath)
{
    printf("[*] Yontem: SetWindowsHookEx\n");

    // 1. Oyun penceresini bul
    HWND hwnd = find_window_by_pid(pid);
    if (!hwnd) {
        printf("[!] Oyun penceresi bulunamadi\n");
        printf("[*] Pencere olmadan thread ID alinamaz\n");
        return FALSE;
    }

    char title[256] = {0};
    GetWindowTextA(hwnd, title, sizeof(title));
    DWORD threadId = GetWindowThreadProcessId(hwnd, NULL);
    printf("[+] Pencere: \"%s\" (thread=%d)\n", title, threadId);

    // 2. DLL'i injector process'e yukle
    HMODULE hDll = LoadLibraryA(dllFullPath);
    if (!hDll) {
        printf("[!] LoadLibrary basarisiz (err=%d)\n", GetLastError());
        printf("    DLL yolu: %s\n", dllFullPath);
        return FALSE;
    }
    printf("[+] DLL yuklendi (injector icinde): %p\n", hDll);

    // 3. HookProc export'unu bul
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
    if (!hookProc) {
        printf("[!] HookProc export'u bulunamadi\n");
        FreeLibrary(hDll);
        return FALSE;
    }
    printf("[+] HookProc: %p\n", hookProc);

    // 4. Hook kur
    HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, hookProc, hDll, threadId);
    if (!hHook) {
        printf("[!] SetWindowsHookEx basarisiz (err=%d)\n", GetLastError());
        FreeLibrary(hDll);
        return FALSE;
    }
    printf("[+] Hook kuruldu: %p\n", hHook);

    // 5. Hook'u tetikle — oyun penceresine mesaj gonder
    PostThreadMessageA(threadId, WM_NULL, 0, 0);
    PostMessageA(hwnd, WM_NULL, 0, 0);
    printf("[*] Tetikleme mesajlari gonderildi\n");

    // 6. DLL'in yuklenmesini bekle
    printf("[*] Bekleniyor (3 saniye)...\n");
    Sleep(3000);

    // 7. Hook kaldir (DLL bellekte kalir, kendini pin'ledi)
    UnhookWindowsHookEx(hHook);
    FreeLibrary(hDll);
    printf("[+] Hook kaldirildi (payload aktif kalmaya devam eder)\n");

    return TRUE;
}

// --- Yontem 2: LoadLibraryA + CreateRemoteThread (fallback) ---

static BOOL inject_loadlibrary(DWORD pid, const char *dllFullPath)
{
    printf("[*] Yontem: LoadLibraryA + CreateRemoteThread\n");

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[!] OpenProcess basarisiz (err=%d)\n", GetLastError());
        return FALSE;
    }

    SIZE_T pathLen = strlen(dllFullPath) + 1;
    PVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen,
                                      MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) {
        printf("[!] VirtualAllocEx basarisiz (err=%d)\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    WriteProcessMemory(hProcess, remotePath, dllFullPath, pathLen, NULL);

    FARPROC pLoadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLib,
                                        remotePath, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread basarisiz (err=%d)\n", GetLastError());
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, 10000);
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode == 0) {
        printf("[!] LoadLibraryA donusu 0 — modul yuklenemedi\n");
        return FALSE;
    }

    printf("[+] DLL yuklendi: 0x%08X\n", exitCode);
    return TRUE;
}

// --- Entry Point ---

int main(int argc, char *argv[])
{
    printf("=== Stealth Injector v3.0 ===\n\n");

    const char *dllPath = (argc > 1) ? argv[1] : "payload.dll";
    const wchar_t *targetProcess = L"KnightOnLine.exe";

    // 1. Tam DLL yolu
    char dllFullPath[MAX_PATH];
    GetFullPathNameA(dllPath, MAX_PATH, dllFullPath, NULL);

    // DLL dosyasini kontrol et
    DWORD attr = GetFileAttributesA(dllFullPath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("[!] DLL bulunamadi: %s\n", dllFullPath);
        return 1;
    }
    printf("[+] DLL: %s\n", dllFullPath);

    // 2. Process bul
    printf("[*] Hedef: KnightOnLine.exe\n");
    DWORD pid = find_process(targetProcess);
    if (!pid) {
        printf("[*] Bekleniyor");
        for (int i = 0; i < 60; i++) {
            pid = find_process(targetProcess);
            if (pid) break;
            printf(".");
            Sleep(1000);
        }
        if (!pid) {
            printf("\n[!] Oyun bulunamadi.\n");
            return 1;
        }
    }
    printf("\n[+] PID: %d\n\n", pid);

    // 3. SetWindowsHookEx dene (ObRegisterCallbacks bypass)
    BOOL ok = inject_hook(pid, dllFullPath);

    // 4. Basarisizsa LoadLibraryA dene
    if (!ok) {
        printf("\n");
        ok = inject_loadlibrary(pid, dllFullPath);
    }

    if (ok) {
        printf("\n[+] BASARILI.\n");
        printf("[*] Log: C:\\ko_payload.log\n");
        printf("[*] Canli takip: powershell Get-Content C:\\ko_payload.log -Wait\n");
    } else {
        printf("\n[!] BASARISIZ.\n");
    }

    return ok ? 0 : 1;
}
