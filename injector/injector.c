// Stealth Injector v2.0 — ASLR Manual Map + Fallback
//
// KnightOnline.exe process'ine payload DLL'i yukler.
// 3 yontem dener:
//   1. Manual map (ASLR, PAGE_READWRITE -> EXECUTE)
//   2. Manual map (OS secimli adres)
//   3. LoadLibraryA fallback (son care)

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

// --- DLL dosyasini oku ---

static BYTE *read_dll_file(const char *path, DWORD *outSize)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    BYTE *buf = (BYTE *)malloc(size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD bytesRead;
    ReadFile(hFile, buf, size, &bytesRead, NULL);
    CloseHandle(hFile);

    *outSize = size;
    return buf;
}

// --- RVA -> File Offset ---

static DWORD rva_to_offset(IMAGE_NT_HEADERS *nt, DWORD rva)
{
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
    }
    return 0;
}

// --- Process handle acma (farkli erisim haklariyla) ---

static HANDLE open_target(DWORD pid)
{
    DWORD accessLevels[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
    };

    for (int i = 0; i < 3; i++) {
        HANDLE h = OpenProcess(accessLevels[i], FALSE, pid);
        if (h) {
            printf("[+] OpenProcess basarili (access=0x%X)\n", accessLevels[i]);
            return h;
        }
        printf("[*] OpenProcess 0x%X basarisiz: %d\n", accessLevels[i], GetLastError());
    }
    return NULL;
}

// --- Bellek tahsisi (coklu strateji) ---

static PVOID alloc_in_target(HANDLE hProcess, DWORD imageSize)
{
    PVOID result = NULL;

    // Strateji 1: PAGE_READWRITE ile rastgele adres (daha az suppheli)
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    DWORD seed = perf.LowPart ^ GetCurrentProcessId() ^ GetTickCount();

    printf("[*] Strateji 1: ASLR + PAGE_READWRITE\n");
    for (int attempt = 0; attempt < 100; attempt++) {
        seed = seed * 1664525 + 1013904223;
        ULONG_PTR candidate = 0x10000000 + (seed % 0x50000000);
        candidate &= ~0xFFFF;

        result = VirtualAllocEx(hProcess, (PVOID)candidate, imageSize,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (result) {
            printf("[+] Tahsis: %p (ASLR+RW)\n", result);
            return result;
        }
    }
    printf("[!] Strateji 1 basarisiz (err=%d)\n", GetLastError());

    // Strateji 2: OS secimli + PAGE_READWRITE
    printf("[*] Strateji 2: OS secimli + PAGE_READWRITE\n");
    result = VirtualAllocEx(hProcess, NULL, imageSize,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (result) {
        printf("[+] Tahsis: %p (OS+RW)\n", result);
        return result;
    }
    printf("[!] Strateji 2 basarisiz (err=%d)\n", GetLastError());

    // Strateji 3: OS secimli + PAGE_EXECUTE_READWRITE
    printf("[*] Strateji 3: OS secimli + PAGE_EXECUTE_READWRITE\n");
    result = VirtualAllocEx(hProcess, NULL, imageSize,
                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (result) {
        printf("[+] Tahsis: %p (OS+RWX)\n", result);
        return result;
    }
    printf("[!] Strateji 3 basarisiz (err=%d)\n", GetLastError());

    return NULL;
}

// --- Shellcode ---

typedef struct {
    FARPROC pLoadLibraryA;
    FARPROC pGetProcAddress;
    FARPROC pVirtualProtect;
    PVOID   moduleBase;
    DWORD   imageSize;
    DWORD   entryPointRVA;
    BOOL    hasRelocations;
} SHELLCODE_PARAMS;

static DWORD WINAPI shellcode_loader(SHELLCODE_PARAMS *params)
{
    typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
    typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
    typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef BOOL (WINAPI *fn_DllMain)(HINSTANCE, DWORD, LPVOID);

    fn_LoadLibraryA myLoadLib = (fn_LoadLibraryA)params->pLoadLibraryA;
    fn_GetProcAddress myGetProc = (fn_GetProcAddress)params->pGetProcAddress;
    fn_VirtualProtect myVP = (fn_VirtualProtect)params->pVirtualProtect;
    BYTE *base = (BYTE *)params->moduleBase;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    // 0. Section'lara execute izni ver
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader +
                                 nt->FileHeader.SizeOfOptionalHeader);
    WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD s = 0; s < nSec; s++) {
        DWORD protect = PAGE_READWRITE;
        DWORD ch = sec[s].Characteristics;
        if ((ch & 0x60000000) == 0x60000000) // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
            protect = PAGE_EXECUTE_READ;
        else if (ch & 0x20000000) // IMAGE_SCN_MEM_EXECUTE
            protect = PAGE_EXECUTE_READWRITE;
        else if (ch & 0x80000000) // IMAGE_SCN_MEM_WRITE
            protect = PAGE_READWRITE;
        else
            protect = PAGE_READONLY;

        if (sec[s].Misc.VirtualSize > 0) {
            DWORD old;
            myVP(base + sec[s].VirtualAddress, sec[s].Misc.VirtualSize, protect, &old);
        }
    }

    // 1. Relocation
    if (params->hasRelocations) {
        ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
        if (delta != 0) {
            DWORD relocRVA = nt->OptionalHeader.DataDirectory[5].VirtualAddress;
            DWORD relocSize = nt->OptionalHeader.DataDirectory[5].Size;

            if (relocRVA && relocSize) {
                DWORD old;
                myVP(base + relocRVA, relocSize, PAGE_READWRITE, &old);

                BYTE *relocBase = base + relocRVA;
                BYTE *relocEnd = relocBase + relocSize;

                while (relocBase < relocEnd) {
                    DWORD pageRVA = *(DWORD *)relocBase;
                    DWORD blockSize = *(DWORD *)(relocBase + 4);
                    if (blockSize == 0) break;

                    DWORD oldPage;
                    myVP(base + pageRVA, 0x1000, PAGE_EXECUTE_READWRITE, &oldPage);

                    WORD *entries = (WORD *)(relocBase + 8);
                    DWORD numEntries = (blockSize - 8) / 2;

                    for (DWORD i = 0; i < numEntries; i++) {
                        WORD type = entries[i] >> 12;
                        WORD offset = entries[i] & 0xFFF;

                        if (type == 3) {
                            DWORD *patch = (DWORD *)(base + pageRVA + offset);
                            *patch += (DWORD)delta;
                        }
                    }

                    myVP(base + pageRVA, 0x1000, oldPage, &oldPage);
                    relocBase += blockSize;
                }
            }
        }
    }

    // 2. Import resolution
    DWORD importRVA = nt->OptionalHeader.DataDirectory[1].VirtualAddress;
    if (importRVA) {
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + importRVA);

        while (imp->Name) {
            char *dllName = (char *)(base + imp->Name);
            HMODULE hMod = myLoadLib(dllName);

            if (hMod) {
                IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
                IMAGE_THUNK_DATA *origThunk = imp->OriginalFirstThunk ?
                    (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk) : thunk;

                while (origThunk->u1.AddressOfData) {
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        thunk->u1.Function = (ULONG_PTR)myGetProc(
                            hMod, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                    } else {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)(base + origThunk->u1.AddressOfData);
                        thunk->u1.Function = (ULONG_PTR)myGetProc(hMod, ibn->Name);
                    }
                    thunk++;
                    origThunk++;
                }
            }
            imp++;
        }
    }

    // 3. TLS callbacks
    DWORD tlsRVA = nt->OptionalHeader.DataDirectory[9].VirtualAddress;
    if (tlsRVA) {
        IMAGE_TLS_DIRECTORY *tls = (IMAGE_TLS_DIRECTORY *)(base + tlsRVA);
        PIMAGE_TLS_CALLBACK *cbs = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
        if (cbs) {
            while (*cbs) {
                (*cbs)((PVOID)base, 1, NULL);
                cbs++;
            }
        }
    }

    // 4. DllMain
    if (params->entryPointRVA) {
        fn_DllMain entry = (fn_DllMain)(base + params->entryPointRVA);
        entry((HINSTANCE)base, 1, NULL);
    }

    return 0;
}

static void shellcode_loader_end(void) {}

// --- Manual Map Inject ---

static BOOL inject_manual_map(HANDLE hProcess, const BYTE *dllData, DWORD dllSize)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dllData;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dllData + dos->e_lfanew);
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    printf("[*] Image size: 0x%X (%d KB)\n", imageSize, imageSize / 1024);

    // 1. Bellek tahsisi
    PVOID remoteBase = alloc_in_target(hProcess, imageSize);
    if (!remoteBase) {
        printf("[!] Tum bellek tahsis stratejileri basarisiz\n");
        return FALSE;
    }

    // 2. Lokal image hazirla
    BYTE *localImage = (BYTE *)calloc(1, imageSize);
    if (!localImage) {
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }

    memcpy(localImage, dllData, nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        memcpy(localImage + sec[i].VirtualAddress,
               dllData + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    // 3. Hedefe yaz
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteBase, localImage, imageSize, &written)) {
        printf("[!] WriteProcessMemory basarisiz (err=%d)\n", GetLastError());
        free(localImage);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] %d byte yazildi\n", (int)written);
    free(localImage);

    // 4. Shellcode parametreleri
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    SHELLCODE_PARAMS params;
    params.pLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");
    params.pGetProcAddress = GetProcAddress(k32, "GetProcAddress");
    params.pVirtualProtect = GetProcAddress(k32, "VirtualProtect");
    params.moduleBase = remoteBase;
    params.imageSize = imageSize;
    params.entryPointRVA = nt->OptionalHeader.AddressOfEntryPoint;
    params.hasRelocations =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0;

    // 5. Params -> hedef
    PVOID remoteParams = VirtualAllocEx(hProcess, NULL, sizeof(params),
                                        MEM_COMMIT, PAGE_READWRITE);
    if (!remoteParams) {
        printf("[!] Parametre bellegi basarisiz (err=%d)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    WriteProcessMemory(hProcess, remoteParams, &params, sizeof(params), NULL);

    // 6. Shellcode -> hedef
    DWORD shellcodeSize = (DWORD)((BYTE *)shellcode_loader_end - (BYTE *)shellcode_loader);
    if (shellcodeSize > 0x10000) shellcodeSize = 0x4000;

    PVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                           MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        printf("[!] Shellcode bellegi basarisiz (err=%d)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    WriteProcessMemory(hProcess, remoteShellcode, shellcode_loader, shellcodeSize, NULL);
    printf("[+] Shellcode yazildi: %p (%d byte)\n", remoteShellcode, shellcodeSize);

    // 7. Calistir
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteShellcode,
                                        remoteParams, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread basarisiz (err=%d)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Remote thread olusturuldu, bekleniyor...\n");
    WaitForSingleObject(hThread, 15000);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] Shellcode tamamlandi (exit: %d)\n", exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);

    printf("[+] Payload aktif: %p\n", remoteBase);
    return TRUE;
}

// --- LoadLibraryA Fallback ---

static BOOL inject_loadlibrary(HANDLE hProcess, const char *dllFullPath)
{
    printf("[*] LoadLibraryA fallback deneniyor...\n");

    SIZE_T pathLen = strlen(dllFullPath) + 1;
    PVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen,
                                      MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) {
        printf("[!] Path bellegi basarisiz (err=%d)\n", GetLastError());
        return FALSE;
    }

    WriteProcessMemory(hProcess, remotePath, dllFullPath, pathLen, NULL);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(k32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLib,
                                        remotePath, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread basarisiz (err=%d)\n", GetLastError());
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] LoadLibraryA thread olusturuldu...\n");
    WaitForSingleObject(hThread, 15000);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);

    if (exitCode == 0) {
        printf("[!] LoadLibraryA basarisiz (modul yuklenemedi)\n");
        return FALSE;
    }

    printf("[+] DLL yuklendi: 0x%08X\n", exitCode);
    return TRUE;
}

// --- Entry Point ---

int main(int argc, char *argv[])
{
    printf("=== Stealth Injector v2.0 ===\n\n");

    const char *dllPath = (argc > 1) ? argv[1] : "payload.dll";
    const wchar_t *targetProcess = L"KnightOnLine.exe";

    // 1. Process bul
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
            printf("\n[!] 60sn beklendi, oyun bulunamadi.\n");
            return 1;
        }
    }
    printf("\n[+] PID: %d\n", pid);

    // 2. DLL oku
    DWORD dllSize;
    BYTE *dllData = read_dll_file(dllPath, &dllSize);
    if (!dllData) {
        printf("[!] DLL okunamadi: %s\n", dllPath);
        return 1;
    }
    printf("[+] DLL yuklendi: %s (%d KB)\n", dllPath, dllSize / 1024);

    // PE dogrulama
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dllData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Gecersiz DOS header\n");
        free(dllData);
        return 1;
    }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dllData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Gecersiz PE header\n");
        free(dllData);
        return 1;
    }

    // 3. Process ac
    HANDLE hProcess = open_target(pid);
    if (!hProcess) {
        printf("[!] Process acilamadi. Yonetici olarak calistirin.\n");
        free(dllData);
        return 1;
    }

    // 4. Manual map dene
    printf("\n[*] Yontem 1: Manual Map\n");
    BOOL ok = inject_manual_map(hProcess, dllData, dllSize);

    // 5. Basarisizsa LoadLibraryA dene
    if (!ok) {
        printf("\n[*] Yontem 2: LoadLibraryA fallback\n");
        char fullPath[MAX_PATH];
        GetFullPathNameA(dllPath, MAX_PATH, fullPath, NULL);
        printf("[*] Tam yol: %s\n", fullPath);
        ok = inject_loadlibrary(hProcess, fullPath);
    }

    CloseHandle(hProcess);
    free(dllData);

    if (ok) {
        printf("\n[+] BASARILI. Payload aktif.\n");
        printf("[*] Log: C:\\ko_payload.log\n");
    } else {
        printf("\n[!] BASARISIZ. Olasi sebepler:\n");
        printf("    1. Yonetici olarak calistirmadiniz\n");
        printf("    2. XIGNCODE handle erisimini engelliyor\n");
        printf("    3. Antivirus mudahale ediyor\n");
        printf("    Cozum: Antivirusu gecici kapatin ve tekrar deneyin.\n");
    }

    return ok ? 0 : 1;
}
