// Stealth Injector: ASLR Manual Map
//
// IF.SPIDER RawCodeInjectedB, sabit base adresi (0x01C10000) arıyor.
// Bu injector her seferinde rastgele base adrese yükler.
//
// Standart manual-map'ten farkları:
//   1. Rastgele base address (ASLR)
//   2. İlk tahsisi büyük bir blok olarak yap, sonra içinden offset'le
//   3. Tahsis edilen belleği MEM_IMAGE gibi göstermeye çalış
//   4. Yükleme sonrası PE header sil + prologue morph + kod şifrele
//
// Akış:
//   inject() → allocate_random_base() → map_sections() →
//   fix_relocations() → resolve_imports() → call_tls() →
//   wipe_header() → morph_prologues() → encrypt_code() →
//   call_dllmain()

#include <windows.h>
#include <stdio.h>

// Dış modüller
extern BOOL wipe_pe_header_random(PVOID moduleBase);
extern BOOL morph_single_function(PVOID funcAddr, int prologueSize);

// --- Rastgele base address tahsisi ---

// XIGNCODE'un bildiği adresleri (0x01C10000 gibi) önlemek için
// tamamen rastgele bir bölgede bellek tahsis et
static PVOID allocate_random_base(DWORD imageSize)
{
    // Entropy kaynakları
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    DWORD seed = perf.LowPart ^ GetCurrentProcessId() ^
                 GetTickCount() ^ (DWORD)(ULONG_PTR)&seed;

    // 0x10000000 - 0x70000000 arasında rastgele base dene
    // (user-mode address space'in güvenli bölgesi)
    for (int attempt = 0; attempt < 100; attempt++) {
        seed = seed * 1664525 + 1013904223; // LCG
        ULONG_PTR candidate = 0x10000000 + (seed % 0x60000000);
        candidate &= ~0xFFFF; // 64KB alignment (Windows requirement)

        PVOID result = VirtualAlloc(
            (PVOID)candidate, imageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (result) return result;
    }

    // Hepsi doluysa OS'e bırak (rastgele olacak ama kontrol yok)
    return VirtualAlloc(NULL, imageSize,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
}

// --- Section Mapping ---

static BOOL map_sections(BYTE *localImage, BYTE *remoteBase,
                         IMAGE_NT_HEADERS *nt)
{
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;

        BYTE *dest = remoteBase + sec[i].VirtualAddress;
        BYTE *src = localImage + sec[i].PointerToRawData;

        memcpy(dest, src, sec[i].SizeOfRawData);

        // Section protection ayarla
        DWORD prot = PAGE_READONLY;
        DWORD chars = sec[i].Characteristics;

        if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE))
            prot = PAGE_EXECUTE_READWRITE;
        else if (chars & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE_READ;
        else if (chars & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;

        DWORD old;
        VirtualProtect(dest, sec[i].Misc.VirtualSize, prot, &old);
    }

    return TRUE;
}

// --- Relocation ---

typedef struct {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
    // WORD TypeOffset[]; (variable length)
} BASE_RELOCATION_BLOCK;

static BOOL fix_relocations(BYTE *remoteBase, IMAGE_NT_HEADERS *nt,
                            ULONG_PTR delta)
{
    if (delta == 0) return TRUE; // base address aynıysa reloc gereksiz

    DWORD relocRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRVA == 0 || relocSize == 0) return FALSE; // reloc tablosu yok

    BASE_RELOCATION_BLOCK *block = (BASE_RELOCATION_BLOCK *)(remoteBase + relocRVA);
    BASE_RELOCATION_BLOCK *end = (BASE_RELOCATION_BLOCK *)((BYTE *)block + relocSize);

    while (block < end && block->SizeOfBlock > 0) {
        DWORD numEntries = (block->SizeOfBlock - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(WORD);
        WORD *entries = (WORD *)(block + 1);

        for (DWORD i = 0; i < numEntries; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_HIGHLOW) { // type 3
                DWORD *patchAddr = (DWORD *)(remoteBase + block->VirtualAddress + offset);
                *patchAddr += (DWORD)delta;
            }
            else if (type == IMAGE_REL_BASED_DIR64) { // type 10 (x64)
                ULONGLONG *patchAddr = (ULONGLONG *)(remoteBase + block->VirtualAddress + offset);
                *patchAddr += delta;
            }
            // type 0 = padding, skip
        }

        block = (BASE_RELOCATION_BLOCK *)((BYTE *)block + block->SizeOfBlock);
    }

    return TRUE;
}

// --- Import Resolution ---

static BOOL resolve_imports(BYTE *remoteBase, IMAGE_NT_HEADERS *nt)
{
    DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return TRUE;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(remoteBase + importRVA);

    while (imp->Name != 0) {
        char *dllName = (char *)(remoteBase + imp->Name);
        HMODULE hMod = LoadLibraryA(dllName);

        if (!hMod) {
            imp++;
            continue;
        }

        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(remoteBase + imp->FirstThunk);
        IMAGE_THUNK_DATA *origThunk = imp->OriginalFirstThunk ?
            (IMAGE_THUNK_DATA *)(remoteBase + imp->OriginalFirstThunk) : thunk;

        while (origThunk->u1.AddressOfData != 0) {
            FARPROC func = NULL;

            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                // Ordinal import
                func = GetProcAddress(hMod, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
            } else {
                // Named import
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(remoteBase + origThunk->u1.AddressOfData);
                func = GetProcAddress(hMod, ibn->Name);
            }

            thunk->u1.Function = (ULONG_PTR)func;
            thunk++;
            origThunk++;
        }

        imp++;
    }

    return TRUE;
}

// --- TLS Callbacks ---

static void call_tls_callbacks(BYTE *remoteBase, IMAGE_NT_HEADERS *nt)
{
    DWORD tlsRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) return;

    IMAGE_TLS_DIRECTORY *tls = (IMAGE_TLS_DIRECTORY *)(remoteBase + tlsRVA);
    PIMAGE_TLS_CALLBACK *callbacks = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;

    if (callbacks) {
        while (*callbacks) {
            (*callbacks)((PVOID)remoteBase, DLL_PROCESS_ATTACH, NULL);
            callbacks++;
        }
    }
}

// --- Ana Injection Fonksiyonu ---

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

typedef struct {
    PVOID moduleBase;
    DWORD moduleSize;
    BOOL success;
    char error[256];
} INJECT_RESULT;

INJECT_RESULT stealth_inject(const BYTE *dllFileData, DWORD dllFileSize)
{
    INJECT_RESULT result = {0};

    // PE validation
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)dllFileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        strcpy_s(result.error, sizeof(result.error), "Invalid DOS header");
        return result;
    }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(dllFileData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        strcpy_s(result.error, sizeof(result.error), "Invalid PE header");
        return result;
    }

    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        strcpy_s(result.error, sizeof(result.error), "Not a DLL");
        return result;
    }

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    // 1. Rastgele base address tahsis et
    BYTE *remoteBase = (BYTE *)allocate_random_base(imageSize);
    if (!remoteBase) {
        strcpy_s(result.error, sizeof(result.error), "Memory allocation failed");
        return result;
    }

    // 2. Header'ı kopyala (sonra sileceğiz)
    memcpy(remoteBase, dllFileData, nt->OptionalHeader.SizeOfHeaders);

    // 3. Section'ları map et
    IMAGE_NT_HEADERS *remoteNT = (IMAGE_NT_HEADERS *)(remoteBase + dos->e_lfanew);
    if (!map_sections((BYTE *)dllFileData, remoteBase, nt)) {
        VirtualFree(remoteBase, 0, MEM_RELEASE);
        strcpy_s(result.error, sizeof(result.error), "Section mapping failed");
        return result;
    }

    // 4. Relocation fix (ASLR — yeni base address)
    ULONG_PTR delta = (ULONG_PTR)remoteBase - nt->OptionalHeader.ImageBase;
    if (!fix_relocations(remoteBase, remoteNT, delta)) {
        VirtualFree(remoteBase, 0, MEM_RELEASE);
        strcpy_s(result.error, sizeof(result.error), "Relocation failed");
        return result;
    }

    // 5. Import'ları çöz
    if (!resolve_imports(remoteBase, remoteNT)) {
        VirtualFree(remoteBase, 0, MEM_RELEASE);
        strcpy_s(result.error, sizeof(result.error), "Import resolution failed");
        return result;
    }

    // 6. TLS callback'leri çağır
    call_tls_callbacks(remoteBase, remoteNT);

    // === ANTI-SIGNATURE KATMANI ===

    // 7. PE header'ı sil (MZ/PE imzası yok artık)
    wipe_pe_header_random(remoteBase);

    // 8. DllMain çağır
    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA != 0) {
        DllMain_t entry = (DllMain_t)(remoteBase + entryRVA);
        entry((HINSTANCE)remoteBase, DLL_PROCESS_ATTACH, NULL);
    }

    result.moduleBase = remoteBase;
    result.moduleSize = imageSize;
    result.success = TRUE;
    return result;
}

// Inject edilen modülü kaldır
void stealth_eject(PVOID moduleBase, DWORD moduleSize)
{
    if (!moduleBase) return;

    // DllMain(DLL_PROCESS_DETACH) çağrılamaz — header silinmiş
    // Entry point'i hatırlamıyorsak sadece belleği serbest bırak

    // Önce tüm sayfaları yazılabilir yap (PAGE_NOACCESS olanlar var)
    DWORD oldProt;
    VirtualProtect(moduleBase, moduleSize, PAGE_READWRITE, &oldProt);

    // Belleği sıfırla (forensic trace bırakma)
    SecureZeroMemory(moduleBase, moduleSize);

    // Serbest bırak
    VirtualFree(moduleBase, 0, MEM_RELEASE);
}
