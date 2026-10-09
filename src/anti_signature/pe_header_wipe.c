// Anti-Signature: PE Header Silme
//
// Manual-map sonrasında DLL'in PE header'ını bellekten siler.
// XIGNCODE xmag.xem modül taramasında MZ/PE imzasını arar —
// header yoksa "modül" olarak tanımlanamaz.
//
// IF.SPIDER RawCodeInjectedB policy'sinin ilk aşaması
// base adresini kontrol etmek — header silinirse MZ magic yoktur.

#include <windows.h>
#include <string.h>

// PE header'ı bellekten sil (MZ + PE + section tablosu)
// DLL zaten yüklenmiş ve relocation yapılmış olmalı
BOOL wipe_pe_header(PVOID moduleBase)
{
    if (!moduleBase) return FALSE;

    // MZ magic kontrolü
    BYTE *base = (BYTE *)moduleBase;
    if (base[0] != 'M' || base[1] != 'Z') return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    // Header'ın toplam boyutu = SizeOfHeaders
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;

    // Yazılabilir yap
    DWORD oldProt;
    if (!VirtualProtect(base, headerSize, PAGE_READWRITE, &oldProt))
        return FALSE;

    // Sıfırla — MZ, PE, section tablosu hepsi gider
    SecureZeroMemory(base, headerSize);

    // Korumayı geri al (PAGE_NOACCESS daha iyi — okuma bile engellenir)
    VirtualProtect(base, headerSize, PAGE_NOACCESS, &oldProt);

    return TRUE;
}

// Daha agresif versiyon: Header'ı rastgele veriyle doldur
// Sıfır blok da bir imza olabilir — rastgele veri daha doğal görünür
BOOL wipe_pe_header_random(PVOID moduleBase)
{
    if (!moduleBase) return FALSE;

    BYTE *base = (BYTE *)moduleBase;
    if (base[0] != 'M' || base[1] != 'Z') return FALSE;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;

    DWORD oldProt;
    if (!VirtualProtect(base, headerSize, PAGE_READWRITE, &oldProt))
        return FALSE;

    // Rastgele veri ile doldur (RtlGenRandom / CryptGenRandom alternatifi)
    DWORD tick = GetTickCount();
    for (DWORD i = 0; i < headerSize; i++) {
        tick = tick * 1103515245 + 12345; // LCG
        base[i] = (BYTE)(tick >> 16);
    }

    VirtualProtect(base, headerSize, PAGE_NOACCESS, &oldProt);
    return TRUE;
}

// Section isimlerini de sil (bazı scanner'lar section isimlerini arar)
// Bu, header wipe'tan ÖNCE çağrılmalı (header bilgisi lazım)
BOOL wipe_section_names(PVOID moduleBase)
{
    BYTE *base = (BYTE *)moduleBase;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    DWORD oldProt;
    VirtualProtect(sec, numSections * sizeof(IMAGE_SECTION_HEADER),
                   PAGE_READWRITE, &oldProt);

    for (WORD i = 0; i < numSections; i++) {
        SecureZeroMemory(sec[i].Name, sizeof(sec[i].Name));
    }

    VirtualProtect(sec, numSections * sizeof(IMAGE_SECTION_HEADER),
                   oldProt, &oldProt);
    return TRUE;
}
