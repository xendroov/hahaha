/*
 * Module Stomping Injector
 *
 * XIGNCODE TH32CS_SNAPMODULE ile modul listesi tarar.
 * Bildigi DLL isimlerini arar (cheat engine, x3.xem, vb).
 * ASLA bir modulun .text section icerigini kontrol etmez.
 *
 * Strateji:
 *   1. Hedef process'e legit bir Windows DLL yukle (cryptbase.dll)
 *   2. O DLL'in .text section'ini payload ile uzerine yaz
 *   3. Modul taramasi: "cryptbase.dll — Microsoft imzali" gorur
 *   4. Gercekte icerideki kod tamamen bizim payload
 *
 * Neden cryptbase.dll:
 *   - Kucuk (~25KB), her zaman System32'de
 *   - Bir cok process zaten yukler
 *   - XIGNCODE whitelist'inde (sistem DLL'i)
 *   - .text section yeterince buyuk
 *
 * Kullanim:
 *   modstom.exe [payload.dll]
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define DECOY_DLL   "cryptbase.dll"
#define TARGET_EXE  L"KnightOnLine.exe"

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

static BYTE *find_remote_module(HANDLE hProc, DWORD pid, const char *modName,
                                DWORD *outSize)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    MODULEENTRY32 me = { .dwSize = sizeof(me) };
    BYTE *base = NULL;

    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, modName) == 0) {
                base = me.modBaseAddr;
                if (outSize) *outSize = me.modBaseSize;
                break;
            }
        } while (Module32Next(snap, &me));
    }

    CloseHandle(snap);
    return base;
}

static BOOL inject_decoy(HANDLE hProc, const char *dllName)
{
    char sysDir[MAX_PATH];
    char fullPath[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    wsprintfA(fullPath, "%s\\%s", sysDir, dllName);

    SIZE_T pathLen = strlen(fullPath) + 1;
    PVOID remotePath = VirtualAllocEx(hProc, NULL, pathLen,
                                      MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) return FALSE;

    WriteProcessMemory(hProc, remotePath, fullPath, pathLen, NULL);

    FARPROC pLoadLib = GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLib,
                                        remotePath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    return TRUE;
}

static BYTE *read_file(const char *path, DWORD *outSize)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD sz = GetFileSize(hFile, NULL);
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read;
    ReadFile(hFile, buf, sz, &read, NULL);
    CloseHandle(hFile);
    *outSize = sz;
    return buf;
}

static BOOL stomp_module(HANDLE hProc, BYTE *decoyBase, DWORD decoySize,
                         const BYTE *payloadFile, DWORD payloadFileSize)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)payloadFile;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Payload gecersiz DOS header\n");
        return FALSE;
    }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(payloadFile + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Payload gecersiz PE header\n");
        return FALSE;
    }

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    if (imageSize > decoySize) {
        printf("[!] Payload (%u) > decoy (%u) — sigmaz\n", imageSize, decoySize);
        printf("[*] Daha buyuk decoy DLL gerekli\n");
        return FALSE;
    }

    BYTE *localImage = (BYTE *)VirtualAlloc(NULL, imageSize,
                                             MEM_COMMIT, PAGE_READWRITE);
    if (!localImage) return FALSE;

    memcpy(localImage, payloadFile, nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        memcpy(localImage + sec[i].VirtualAddress,
               payloadFile + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    ULONG_PTR delta = (ULONG_PTR)decoyBase - nt->OptionalHeader.ImageBase;

    if (delta != 0) {
        DWORD relocRVA = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (relocRVA && relocSize) {
            BYTE *block = localImage + relocRVA;
            BYTE *end = block + relocSize;

            while (block < end) {
                DWORD va   = *(DWORD *)block;
                DWORD bsz  = *(DWORD *)(block + 4);
                if (bsz == 0) break;

                DWORD numEntries = (bsz - 8) / 2;
                WORD *entries = (WORD *)(block + 8);

                for (DWORD i = 0; i < numEntries; i++) {
                    WORD type   = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;

                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD *patch = (DWORD *)(localImage + va + offset);
                        *patch += (DWORD)delta;
                    }
                }
                block += bsz;
            }
            printf("[+] Relocation: delta=0x%08X\n", (DWORD)delta);
        }
    }

    IMAGE_IMPORT_DESCRIPTOR *imp = NULL;
    DWORD impRVA = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (impRVA) {
        imp = (IMAGE_IMPORT_DESCRIPTOR *)(localImage + impRVA);
        while (imp->Name) {
            char *dllName = (char *)(localImage + imp->Name);

            HMODULE hMod = GetModuleHandleA(dllName);
            if (!hMod) hMod = LoadLibraryA(dllName);
            if (!hMod) { imp++; continue; }

            IMAGE_THUNK_DATA *thunk =
                (IMAGE_THUNK_DATA *)(localImage + imp->FirstThunk);
            IMAGE_THUNK_DATA *origThunk = imp->OriginalFirstThunk
                ? (IMAGE_THUNK_DATA *)(localImage + imp->OriginalFirstThunk)
                : thunk;

            while (origThunk->u1.AddressOfData) {
                FARPROC func = NULL;
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    func = GetProcAddress(hMod,
                        (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)
                        (localImage + origThunk->u1.AddressOfData);
                    func = GetProcAddress(hMod, ibn->Name);
                }
                thunk->u1.Function = (ULONG_PTR)func;
                thunk++;
                origThunk++;
            }
            imp++;
        }
        printf("[+] Import'lar cozuldu\n");
    }

    DWORD old;
    VirtualProtectEx(hProc, decoyBase, imageSize,
                     PAGE_EXECUTE_READWRITE, &old);

    SIZE_T written;
    BOOL ok = WriteProcessMemory(hProc, decoyBase, localImage,
                                  imageSize, &written);
    if (!ok) {
        printf("[!] WriteProcessMemory basarisiz (err=%d)\n", GetLastError());
        VirtualFree(localImage, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] %u byte yazildi @%p (decoy uzerine)\n",
           (DWORD)written, decoyBase);

    VirtualProtectEx(hProc, decoyBase, imageSize, old, &old);

    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA) {
        BYTE *remoteEntry = decoyBase + entryRVA;
        printf("[+] DllMain @%p\n", remoteEntry);

        typedef struct {
            BYTE code[64];
            ULONG_PTR hModule;
            ULONG_PTR reason;
            ULONG_PTR reserved;
            ULONG_PTR entryPoint;
        } SHELLCODE_CONTEXT;

        SHELLCODE_CONTEXT *ctx = (SHELLCODE_CONTEXT *)VirtualAllocEx(
            hProc, NULL, sizeof(SHELLCODE_CONTEXT),
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (ctx) {
            SHELLCODE_CONTEXT local = {0};
            local.hModule    = (ULONG_PTR)decoyBase;
            local.reason     = DLL_PROCESS_ATTACH;
            local.reserved   = 0;
            local.entryPoint = (ULONG_PTR)remoteEntry;

            /*
             * shellcode (x86):
             *   mov eax, [ecx + 0x44]  ; entryPoint
             *   push 0                 ; reserved
             *   push 1                 ; DLL_PROCESS_ATTACH
             *   push [ecx + 0x40]      ; hModule
             *   call eax               ; DllMain(hModule, 1, NULL)
             *   ret
             */
            BYTE sc[] = {
                0x8B, 0x81, 0x4C, 0x00, 0x00, 0x00,       // mov eax, [ecx+0x4C]
                0x6A, 0x00,                                 // push 0
                0x6A, 0x01,                                 // push 1
                0xFF, 0xB1, 0x40, 0x00, 0x00, 0x00,        // push [ecx+0x40]
                0xFF, 0xD0,                                 // call eax
                0xC3                                        // ret
            };
            memcpy(local.code, sc, sizeof(sc));

            WriteProcessMemory(hProc, ctx, &local, sizeof(local), NULL);

            HANDLE hThread = CreateRemoteThread(
                hProc, NULL, 0,
                (LPTHREAD_START_ROUTINE)ctx,
                NULL, 0, NULL);

            if (hThread) {
                WaitForSingleObject(hThread, 10000);
                CloseHandle(hThread);
                printf("[+] DllMain cagirildi (stomped module icinden)\n");
            }
        }
    }

    VirtualFree(localImage, 0, MEM_RELEASE);
    return TRUE;
}

int main(int argc, char *argv[])
{
    printf("=== Module Stomping Injector ===\n");
    printf("    Decoy: %s (Microsoft imzali)\n\n", DECOY_DLL);

    const char *payloadPath = (argc > 1) ? argv[1] : "payload.dll";

    char fullPath[MAX_PATH];
    GetFullPathNameA(payloadPath, MAX_PATH, fullPath, NULL);

    if (GetFileAttributesA(fullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] Payload bulunamadi: %s\n", fullPath);
        return 1;
    }
    printf("[+] Payload: %s\n", fullPath);

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
        PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[!] OpenProcess basarisiz (err=%d)\n", GetLastError());
        printf("[*] XIGNCODE ObRegisterCallbacks aktif olabilir\n");
        printf("[*] Thread hijack yontemini deneyin: thijack.exe\n");
        return 1;
    }

    DWORD decoySize = 0;
    BYTE *decoyBase = find_remote_module(hProc, pid, DECOY_DLL, &decoySize);

    if (!decoyBase) {
        printf("[*] %s hedef process'te yok, yukleniyor...\n", DECOY_DLL);
        if (!inject_decoy(hProc, DECOY_DLL)) {
            printf("[!] Decoy DLL yuklenemedi\n");
            CloseHandle(hProc);
            return 1;
        }
        Sleep(500);
        decoyBase = find_remote_module(hProc, pid, DECOY_DLL, &decoySize);
        if (!decoyBase) {
            printf("[!] Decoy DLL bulunamadi\n");
            CloseHandle(hProc);
            return 1;
        }
    }
    printf("[+] Decoy %s @%p (sz=0x%X)\n", DECOY_DLL, decoyBase, decoySize);

    DWORD payloadFileSize;
    BYTE *payloadFile = read_file(fullPath, &payloadFileSize);
    if (!payloadFile) {
        printf("[!] Payload okunamadi\n");
        CloseHandle(hProc);
        return 1;
    }

    BOOL ok = stomp_module(hProc, decoyBase, decoySize,
                           payloadFile, payloadFileSize);

    VirtualFree(payloadFile, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (ok)
        printf("\n[+] MODULE STOMPING BASARILI\n"
               "[*] XIGNCODE modul taramasinda: %s (Microsoft)\n"
               "[*] Gercek icerik: payload.dll\n", DECOY_DLL);
    else
        printf("\n[!] BASARISIZ\n");

    return ok ? 0 : 1;
}
