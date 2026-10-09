// Anti-Signature: Runtime Kod Şifreleme
//
// IF.SPIDER RawCodeInjectedB, executable bellekteki byte pattern'ları tarıyor.
// Çözüm: Kod çalışmadığında şifreli tut, sadece çalışacak sayfayı aç.
//
// Mekanizma:
//   1. DLL yüklendikten sonra tüm .text section'ını XOR ile şifrele
//   2. VEH (Vectored Exception Handler) kur
//   3. Şifreli sayfa çalıştırılmaya çalışınca → PAGE_NOACCESS violation
//   4. VEH handler: sayfayı decrypt et, PAGE_EXECUTE_READ yap
//   5. Guard page veya timer ile tekrar encrypt et
//
// Sonuç: Herhangi bir anda bellekte sadece 1 sayfa (4KB) açık
// XIGNCODE tarama yapsa bile kalan sayfalar şifreli görünür

#include <windows.h>
#include <string.h>
#include <stdio.h>

#define PAGE_SIZE_4K 0x1000

typedef struct {
    BYTE *sectionBase;      // .text section başlangıcı
    DWORD sectionSize;      // .text section boyutu
    BYTE *xorKeyStream;     // Her sayfa için farklı XOR anahtarı
    DWORD numPages;         // Toplam sayfa sayısı
    BOOL *pageEncrypted;    // Her sayfanın şifreli olup olmadığı
    PVOID vehHandle;        // VEH handler handle'ı
    DWORD activePageIndex;  // Şu an açık olan sayfa (-1 = hepsi şifreli)
    CRITICAL_SECTION lock;  // Thread safety
    BOOL initialized;
} CODE_CRYPT_CTX;

static CODE_CRYPT_CTX g_crypt = {0};

// XOR key stream oluştur (her sayfa için farklı anahtar)
static void generate_key_stream(BYTE *keys, DWORD numPages)
{
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    DWORD seed = counter.LowPart ^ GetCurrentProcessId() ^ GetTickCount();

    for (DWORD i = 0; i < numPages; i++) {
        seed = seed * 1103515245 + 12345;
        keys[i] = (BYTE)((seed >> 16) & 0xFF);
        if (keys[i] == 0) keys[i] = 0xAA; // sıfır key'den kaçın
    }
}

// Tek bir sayfayı XOR ile şifrele/çöz (toggle)
static void xor_page(BYTE *pageBase, BYTE key)
{
    // 4-byte aligned XOR (daha hızlı)
    DWORD key32 = key | (key << 8) | (key << 16) | (key << 24);
    DWORD *p = (DWORD *)pageBase;
    for (int i = 0; i < PAGE_SIZE_4K / 4; i++) {
        p[i] ^= key32;
    }
}

// Sayfayı şifrele (PAGE_NOACCESS yap)
static BOOL encrypt_page(DWORD pageIndex)
{
    if (pageIndex >= g_crypt.numPages) return FALSE;
    if (g_crypt.pageEncrypted[pageIndex]) return TRUE;

    BYTE *pageBase = g_crypt.sectionBase + (pageIndex * PAGE_SIZE_4K);

    DWORD oldProt;
    VirtualProtect(pageBase, PAGE_SIZE_4K, PAGE_READWRITE, &oldProt);
    xor_page(pageBase, g_crypt.xorKeyStream[pageIndex]);
    VirtualProtect(pageBase, PAGE_SIZE_4K, PAGE_NOACCESS, &oldProt);

    g_crypt.pageEncrypted[pageIndex] = TRUE;
    return TRUE;
}

// Sayfayı çöz (PAGE_EXECUTE_READ yap)
static BOOL decrypt_page(DWORD pageIndex)
{
    if (pageIndex >= g_crypt.numPages) return FALSE;
    if (!g_crypt.pageEncrypted[pageIndex]) return TRUE;

    BYTE *pageBase = g_crypt.sectionBase + (pageIndex * PAGE_SIZE_4K);

    DWORD oldProt;
    VirtualProtect(pageBase, PAGE_SIZE_4K, PAGE_READWRITE, &oldProt);
    xor_page(pageBase, g_crypt.xorKeyStream[pageIndex]);
    VirtualProtect(pageBase, PAGE_SIZE_4K, PAGE_EXECUTE_READ, &oldProt);

    g_crypt.pageEncrypted[pageIndex] = FALSE;
    return TRUE;
}

// VEH Handler — şifreli sayfaya erişim gelince çöz
static LONG CALLBACK crypt_veh_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID faultAddr = (PVOID)ep->ExceptionRecord->ExceptionInformation[1];
    BYTE *addr = (BYTE *)faultAddr;

    // Bizim section'ımızda mı?
    if (addr < g_crypt.sectionBase ||
        addr >= g_crypt.sectionBase + g_crypt.sectionSize) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD pageIndex = (DWORD)(addr - g_crypt.sectionBase) / PAGE_SIZE_4K;

    EnterCriticalSection(&g_crypt.lock);

    // Önceki aktif sayfayı tekrar şifrele (sliding window)
    if (g_crypt.activePageIndex != (DWORD)-1 &&
        g_crypt.activePageIndex != pageIndex) {
        encrypt_page(g_crypt.activePageIndex);
    }

    // Yeni sayfayı çöz
    decrypt_page(pageIndex);
    g_crypt.activePageIndex = pageIndex;

    LeaveCriticalSection(&g_crypt.lock);

    return EXCEPTION_CONTINUE_EXECUTION;
}

// --- Public API ---

// Kod şifrelemeyi başlat (DLL yüklendikten sonra çağır)
BOOL code_crypt_init(PVOID moduleBase)
{
    if (g_crypt.initialized) return TRUE;

    BYTE *base = (BYTE *)moduleBase;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    // .text section'ını bul
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            g_crypt.sectionBase = base + sec[i].VirtualAddress;
            g_crypt.sectionSize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!g_crypt.sectionBase) return FALSE;

    // Sayfa sayısı
    g_crypt.numPages = (g_crypt.sectionSize + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;

    // Key stream
    g_crypt.xorKeyStream = (BYTE *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, g_crypt.numPages);

    // Encrypted flags
    g_crypt.pageEncrypted = (BOOL *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, g_crypt.numPages * sizeof(BOOL));

    if (!g_crypt.xorKeyStream || !g_crypt.pageEncrypted) return FALSE;

    generate_key_stream(g_crypt.xorKeyStream, g_crypt.numPages);
    InitializeCriticalSection(&g_crypt.lock);

    // VEH kur (en yüksek öncelik)
    g_crypt.vehHandle = AddVectoredExceptionHandler(1, crypt_veh_handler);
    if (!g_crypt.vehHandle) return FALSE;

    g_crypt.activePageIndex = (DWORD)-1;
    g_crypt.initialized = TRUE;

    // Tüm sayfaları şifrele (aktif çalışan sayfa hariç)
    // NOT: Bu fonksiyonun kendisi de .text'te — kendi sayfamızı şifrelememeliyiz
    DWORD selfPage = (DWORD)((BYTE *)code_crypt_init - g_crypt.sectionBase) / PAGE_SIZE_4K;

    for (DWORD i = 0; i < g_crypt.numPages; i++) {
        if (i == selfPage) continue; // kendi sayfamızı atla
        encrypt_page(i);
    }

    return TRUE;
}

// Şifrelemeyi kapat ve tüm sayfaları aç (cleanup)
void code_crypt_shutdown(void)
{
    if (!g_crypt.initialized) return;

    EnterCriticalSection(&g_crypt.lock);

    // Tüm sayfaları decrypt et
    for (DWORD i = 0; i < g_crypt.numPages; i++) {
        if (g_crypt.pageEncrypted[i]) {
            decrypt_page(i);
        }
    }

    if (g_crypt.vehHandle) {
        RemoveVectoredExceptionHandler(g_crypt.vehHandle);
        g_crypt.vehHandle = NULL;
    }

    LeaveCriticalSection(&g_crypt.lock);
    DeleteCriticalSection(&g_crypt.lock);

    if (g_crypt.xorKeyStream)
        HeapFree(GetProcessHeap(), 0, g_crypt.xorKeyStream);
    if (g_crypt.pageEncrypted)
        HeapFree(GetProcessHeap(), 0, g_crypt.pageEncrypted);

    g_crypt.initialized = FALSE;
}

// Belirli bir adres aralığını kalıcı olarak açık tut
// (sık çağrılan fonksiyonlar için — performance)
BOOL code_crypt_whitelist(PVOID addr, DWORD size)
{
    if (!g_crypt.initialized) return FALSE;

    BYTE *a = (BYTE *)addr;
    if (a < g_crypt.sectionBase ||
        a >= g_crypt.sectionBase + g_crypt.sectionSize)
        return FALSE;

    DWORD startPage = (DWORD)(a - g_crypt.sectionBase) / PAGE_SIZE_4K;
    DWORD endPage = (DWORD)(a + size - g_crypt.sectionBase) / PAGE_SIZE_4K;

    EnterCriticalSection(&g_crypt.lock);
    for (DWORD i = startPage; i <= endPage && i < g_crypt.numPages; i++) {
        decrypt_page(i);
        // Encrypted flag'i set etmeyerek kalıcı açık bırak
        // (encrypt_page tekrar çağrılmayacak)
    }
    LeaveCriticalSection(&g_crypt.lock);

    return TRUE;
}
