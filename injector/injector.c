// Stealth Injector — ASLR Manual Map
//
// KnightOnline.exe process'ine payload DLL'i yükler.
// Standart manual-map'ten farkları:
//   1. Her seferinde rastgele base address (0x01C10000 sabit değil)
//   2. Injection sonrası PE header sil
//   3. İşlem bitince injector'ı hızlıca kapat (process scan'de görünmesin)
//
// Kullanım: injector.exe [payload.dll yolu]
//
// IF.SPIDER RawCodeInjectedB bypass:
//   - Sabit base (0x01C10000) → rastgele ASLR base
//   - MZ header → injection sonrası siliniyor (payload içinden)
//   - MSVC prologue → payload kendi prologlarını morph ediyor

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

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

// --- DLL dosyasını oku ---

static BYTE *read_dll_file(const char *path, DWORD *outSize)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    BYTE *buf = (BYTE *)malloc(size);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read;
    ReadFile(hFile, buf, size, &read, NULL);
    CloseHandle(hFile);

    *outSize = size;
    return buf;
}

// --- RVA → File Offset ---

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

// --- Rastgele base address ---

static PVOID alloc_random_in_target(HANDLE hProcess, DWORD imageSize)
{
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    DWORD seed = perf.LowPart ^ GetCurrentProcessId() ^ GetTickCount();

    for (int attempt = 0; attempt < 200; attempt++) {
        seed = seed * 1664525 + 1013904223;
        ULONG_PTR candidate = 0x10000000 + (seed % 0x50000000);
        candidate &= ~0xFFFF; // 64KB align

        PVOID result = VirtualAllocEx(hProcess, (PVOID)candidate, imageSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (result) return result;
    }

    // Fallback: OS seçsin
    return VirtualAllocEx(hProcess, NULL, imageSize,
                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// --- Manual Map ---

typedef struct {
    // Payload'ın ihtiyaç duyacağı fonksiyon adresleri
    FARPROC pLoadLibraryA;
    FARPROC pGetProcAddress;
    PVOID   moduleBase;
    DWORD   imageSize;
    DWORD   entryPointRVA;
    BOOL    hasRelocations;
} SHELLCODE_PARAMS;

// Shellcode: hedef process'te çalışacak mini loader
// Relocation + import resolution + DllMain çağrısı yapar
// Bu shellcode'u hedef process'e yazıp CreateRemoteThread ile çalıştırıyoruz
//
// NOT: Bu fonksiyon shellcode olarak derlenecek — extern çağrı yapamaz,
// string literal kullanamaz, global değişkene erişemez.
// Tüm veriler SHELLCODE_PARAMS üzerinden gelir.
static DWORD WINAPI shellcode_loader(SHELLCODE_PARAMS *params)
{
    typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
    typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
    typedef BOOL (WINAPI *fn_DllMain)(HINSTANCE, DWORD, LPVOID);

    fn_LoadLibraryA myLoadLib = (fn_LoadLibraryA)params->pLoadLibraryA;
    fn_GetProcAddress myGetProc = (fn_GetProcAddress)params->pGetProcAddress;
    BYTE *base = (BYTE *)params->moduleBase;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    // 1. Relocation
    if (params->hasRelocations) {
        ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
        if (delta != 0) {
            DWORD relocRVA = nt->OptionalHeader.DataDirectory[5].VirtualAddress;
            DWORD relocSize = nt->OptionalHeader.DataDirectory[5].Size;

            if (relocRVA && relocSize) {
                BYTE *relocBase = base + relocRVA;
                BYTE *relocEnd = relocBase + relocSize;

                while (relocBase < relocEnd) {
                    DWORD pageRVA = *(DWORD *)relocBase;
                    DWORD blockSize = *(DWORD *)(relocBase + 4);
                    if (blockSize == 0) break;

                    WORD *entries = (WORD *)(relocBase + 8);
                    DWORD numEntries = (blockSize - 8) / 2;

                    for (DWORD i = 0; i < numEntries; i++) {
                        WORD type = entries[i] >> 12;
                        WORD offset = entries[i] & 0xFFF;

                        if (type == 3) { // IMAGE_REL_BASED_HIGHLOW
                            DWORD *patch = (DWORD *)(base + pageRVA + offset);
                            *patch += (DWORD)delta;
                        }
                    }

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
                (*cbs)((PVOID)base, 1 /*DLL_PROCESS_ATTACH*/, NULL);
                cbs++;
            }
        }
    }

    // 4. DllMain
    if (params->entryPointRVA) {
        fn_DllMain entry = (fn_DllMain)(base + params->entryPointRVA);
        entry((HINSTANCE)base, 1 /*DLL_PROCESS_ATTACH*/, NULL);
    }

    return 0;
}

// Shellcode sonu marker (boyut hesaplama için)
static void shellcode_loader_end(void) {}

// --- Ana inject fonksiyonu ---

static BOOL inject(HANDLE hProcess, const BYTE *dllData, DWORD dllSize)
{
    // PE validation
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dllData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Gecersiz DOS header\n");
        return FALSE;
    }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dllData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Gecersiz PE header\n");
        return FALSE;
    }

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    printf("[*] Image size: 0x%X (%d KB)\n", imageSize, imageSize / 1024);

    // 1. Rastgele base address tahsis et
    PVOID remoteBase = alloc_random_in_target(hProcess, imageSize);
    if (!remoteBase) {
        printf("[!] Bellek tahsisi basarisiz\n");
        return FALSE;
    }
    printf("[+] Tahsis edilen base: %p (ASLR)\n", remoteBase);

    // 2. Header + section'ları geçici buffer'a hazırla
    BYTE *localImage = (BYTE *)calloc(1, imageSize);
    if (!localImage) {
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }

    // Header kopyala
    memcpy(localImage, dllData, nt->OptionalHeader.SizeOfHeaders);

    // Section'ları kopyala
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        memcpy(localImage + sec[i].VirtualAddress,
               dllData + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    // 3. Image'ı hedef process'e yaz
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteBase, localImage, imageSize, &written)) {
        printf("[!] WriteProcessMemory basarisiz: %d\n", GetLastError());
        free(localImage);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] %d byte yazildi\n", (int)written);

    free(localImage);

    // 4. Shellcode parametrelerini hazırla
    SHELLCODE_PARAMS params;
    params.pLoadLibraryA = (FARPROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    params.pGetProcAddress = (FARPROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    params.moduleBase = remoteBase;
    params.imageSize = imageSize;
    params.entryPointRVA = nt->OptionalHeader.AddressOfEntryPoint;
    params.hasRelocations =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0;

    // 5. Parametre yapısını hedef process'e yaz
    PVOID remoteParams = VirtualAllocEx(hProcess, NULL, sizeof(params),
                                        MEM_COMMIT, PAGE_READWRITE);
    if (!remoteParams) {
        printf("[!] Parametre bellegi tahsis edilemedi\n");
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    WriteProcessMemory(hProcess, remoteParams, &params, sizeof(params), NULL);

    // 6. Shellcode'u hedef process'e yaz
    DWORD shellcodeSize = (DWORD)((BYTE *)shellcode_loader_end - (BYTE *)shellcode_loader);
    if (shellcodeSize > 0x10000) shellcodeSize = 0x4000; // güvenlik sınırı

    PVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                           MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        printf("[!] Shellcode bellegi tahsis edilemedi\n");
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }
    WriteProcessMemory(hProcess, remoteShellcode, shellcode_loader, shellcodeSize, NULL);

    printf("[+] Shellcode yazildi: %p (%d byte)\n", remoteShellcode, shellcodeSize);

    // 7. Remote thread ile shellcode'u çalıştır
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteShellcode,
                                        remoteParams, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread basarisiz: %d\n", GetLastError());
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Remote thread olusturuldu, bekleniyor...\n");
    WaitForSingleObject(hThread, 10000); // 10sn timeout

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] Shellcode tamamlandi (exit: %d)\n", exitCode);

    // Temizlik — shellcode ve params belleğini serbest bırak
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);

    // remoteBase'i BIRAKMA — payload orada çalışıyor
    printf("[+] Payload aktif: %p\n", remoteBase);
    return TRUE;
}

// --- Entry Point ---

int main(int argc, char *argv[])
{
    printf("=== Stealth Injector v1.0 ===\n\n");

    const char *dllPath = (argc > 1) ? argv[1] : "payload.dll";
    const wchar_t *targetProcess = L"KnightOnLine.exe";

    // 1. Hedef process'i bul
    printf("[*] Hedef: KnightOnLine.exe\n");
    DWORD pid = find_process(targetProcess);
    if (!pid) {
        printf("[!] KnightOnLine.exe bulunamadi. Once oyunu baslatin.\n");
        printf("    Bekleniyor");
        for (int i = 0; i < 60; i++) {
            pid = find_process(targetProcess);
            if (pid) break;
            printf(".");
            Sleep(1000);
        }
        if (!pid) {
            printf("\n[!] 60 saniye beklendi, oyun bulunamadi.\n");
            return 1;
        }
    }
    printf("\n[+] PID: %d\n", pid);

    // 2. DLL dosyasını oku
    DWORD dllSize;
    BYTE *dllData = read_dll_file(dllPath, &dllSize);
    if (!dllData) {
        printf("[!] DLL okunamadi: %s\n", dllPath);
        return 1;
    }
    printf("[+] DLL yuklendi: %s (%d KB)\n", dllPath, dllSize / 1024);

    // 3. Process'i aç
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] OpenProcess basarisiz: %d\n", GetLastError());
        printf("    Yonetici olarak calistirin.\n");
        free(dllData);
        return 1;
    }

    // 4. Inject
    printf("[*] Injection baslatiliyor...\n");
    BOOL ok = inject(hProcess, dllData, dllSize);

    CloseHandle(hProcess);
    free(dllData);

    if (ok) {
        printf("\n[+] BASARILI. Payload aktif.\n");
        printf("[*] Log dosyasi: %%TEMP%%\\stealth_main.log\n");
        printf("[*] Injector kapaniyor (process scan'de gorunmesin).\n");
    } else {
        printf("\n[!] BASARISIZ.\n");
    }

    return ok ? 0 : 1;
}
