// Anti-Signature: Function Prologue Metamorphism
//
// IF.SPIDER RawCodeInjectedB, MSVC fonksiyon prologlarını arıyor:
//   55 8B EC 83 EC xx  (push ebp; mov ebp,esp; sub esp,N)
//
// Bu modül, derlenen DLL'in tüm fonksiyon prologlarını runtime'da
// semantik olarak eşdeğer ama farklı opcode dizilimlerine dönüştürür.
//
// Örnek dönüşüm:
//   Orijinal:  55 8B EC 83 EC 6C
//              push ebp; mov ebp, esp; sub esp, 0x6C
//
//   Morphed:   8B EC 55 83 C4 94
//              mov ebp, esp; push ebp; add esp, -0x6C
//   (semantik olarak aynı — ebp = eski esp, esp -= 0x6C)
//
//   Veya NOP-padded:
//              55 89 E5 81 EC 6C 00 00 00
//              push ebp; mov ebp, esp; sub esp, 0x6C (32-bit immediate)

#include <windows.h>
#include <string.h>
#include <stdio.h>

// Bilinen MSVC prologue pattern'leri
typedef struct {
    BYTE pattern[16];
    BYTE mask[16];    // 0xFF = exact match, 0x00 = wildcard
    int length;
    const char *name;
} PROLOGUE_PATTERN;

static PROLOGUE_PATTERN g_known_prologues[] = {
    // Pattern 1: push ebp; mov ebp, esp; sub esp, imm8
    { {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}, 6, "stdcall_sub8" },

    // Pattern 2: push ebp; mov ebp, esp; sub esp, imm32
    { {0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}, 9, "stdcall_sub32" },

    // Pattern 3: push ebp; mov ebp, esp; push -1 (SEH frame)
    { {0x55, 0x8B, 0xEC, 0x6A, 0xFF},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5, "seh_frame" },

    // Pattern 4: push ebp; mov ebp, esp; and esp, -8 (alignment)
    { {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0x00},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}, 6, "aligned" },

    // Pattern 5: mov edi, edi; push ebp; mov ebp, esp (hotpatchable)
    { {0x8B, 0xFF, 0x55, 0x8B, 0xEC},
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 5, "hotpatch" },
};

#define NUM_PROLOGUES (sizeof(g_known_prologues) / sizeof(g_known_prologues[0]))

// Pattern eşleşme kontrolü
static BOOL match_pattern(const BYTE *code, const PROLOGUE_PATTERN *pat)
{
    for (int i = 0; i < pat->length; i++) {
        if ((code[i] & pat->mask[i]) != (pat->pattern[i] & pat->mask[i]))
            return FALSE;
    }
    return TRUE;
}

// --- Morphing Stratejileri ---

// Strateji 1: Eşdeğer instruction substitution
// push ebp (55) → lea esp,[esp-4]; mov [esp],ebp (8D 64 24 FC 89 2C 24)
// mov ebp,esp (8B EC) → mov ebp,esp (89 E5) [alternatif encoding]
// sub esp,N (83 EC xx) → add esp,-N (83 C4 xx) [signed]
static int morph_substitute(BYTE *code, int origLen, BYTE *out, int maxOut)
{
    int pos = 0;

    if (origLen >= 3 && code[0] == 0x55 && code[1] == 0x8B && code[2] == 0xEC) {
        // push ebp → sub esp,4; mov [esp],ebp
        out[pos++] = 0x83; out[pos++] = 0xEC; out[pos++] = 0x04; // sub esp, 4
        out[pos++] = 0x89; out[pos++] = 0x2C; out[pos++] = 0x24; // mov [esp], ebp
        // mov ebp, esp → lea ebp, [esp+4]... hayır, semantik olarak mov ebp,esp
        // alternatif encoding: 89 E5 (mov ebp, esp — r/m32 encoding)
        out[pos++] = 0x89; out[pos++] = 0xE5;

        // sub esp, N → add esp, -N
        if (origLen >= 6 && code[3] == 0x83 && code[4] == 0xEC) {
            BYTE n = code[5];
            out[pos++] = 0x83; out[pos++] = 0xC4;
            out[pos++] = (BYTE)(-(signed char)n); // add esp, -N
        }
    }

    return pos;
}

// Strateji 2: NOP sled + reorder
// Fonksiyonun önüne rastgele uzunlukta "junk" ekle
// JMP ile gerçek koda atla
static int morph_nop_sled(BYTE *code, int origLen, BYTE *out, int maxOut)
{
    int pos = 0;

    // Rastgele 2-8 byte "dead code" (asla çalışmaz — JMP atlar)
    DWORD tick = GetTickCount();
    int sledLen = 2 + (tick % 7);

    // JMP rel8 ile sled'i atla
    out[pos++] = 0xEB;           // JMP short
    out[pos++] = (BYTE)sledLen;  // sled uzunluğu

    // Rastgele ama geçerli görünen byte'lar
    for (int i = 0; i < sledLen; i++) {
        tick = tick * 1103515245 + 12345;
        // Geçerli x86 instruction gibi görünen byte'lar
        BYTE candidates[] = {
            0x90, // NOP
            0x50, 0x51, 0x52, 0x53, // push reg
            0x58, 0x59, 0x5A, 0x5B, // pop reg
            0x40, 0x41, 0x42, 0x43, // inc reg
            0x48, 0x49, 0x4A, 0x4B, // dec reg
        };
        out[pos++] = candidates[(tick >> 16) % sizeof(candidates)];
    }

    // Orijinal kodu kopyala
    memcpy(out + pos, code, origLen);
    pos += origLen;

    return pos;
}

// Strateji 3: XOR encoding + decode stub
// Fonksiyonun ilk N byte'ını XOR ile şifrele
// Çağrıldığında önce decode et, çalıştır, tekrar encode et
static int morph_xor_encode(BYTE *code, int origLen, BYTE *out, int maxOut,
                            BYTE xorKey)
{
    int pos = 0;

    // Self-decoding stub:
    //   pushad
    //   lea esi, [encoded_data]
    //   mov ecx, origLen
    //   xor_loop: xor byte [esi], key
    //   inc esi
    //   loop xor_loop
    //   popad
    //   jmp decoded_code

    out[pos++] = 0x60; // pushad

    // lea esi, [eip + offset_to_data]
    out[pos++] = 0xE8; // call $+5 (EIP trick)
    *(DWORD *)(out + pos) = 0; pos += 4;
    out[pos++] = 0x5E; // pop esi (esi = current EIP)
    // esi şu an "pop esi" instruction'ından sonrasını gösteriyor
    // encoded data'ya offset hesapla
    int stubRemaining = 10; // kalan stub byte'ları (yaklaşık)
    out[pos++] = 0x83; out[pos++] = 0xC6;
    out[pos++] = (BYTE)stubRemaining; // add esi, offset

    // mov ecx, origLen
    out[pos++] = 0xB9;
    *(DWORD *)(out + pos) = origLen; pos += 4;

    // xor_loop:
    int loopAddr = pos;
    out[pos++] = 0x80; out[pos++] = 0x36; out[pos++] = xorKey; // xor byte [esi], key
    out[pos++] = 0x46; // inc esi
    out[pos++] = 0xE2; // loop
    out[pos++] = (BYTE)(loopAddr - pos - 1); // relative offset (negative)

    out[pos++] = 0x61; // popad

    // Encoded data (orijinal kod XOR'lanmış)
    for (int i = 0; i < origLen; i++) {
        out[pos++] = code[i] ^ xorKey;
    }

    return pos;
}

// --- Ana Morph Fonksiyonu ---

typedef struct {
    PVOID moduleBase;
    DWORD moduleSize;
    int morphedCount;
    int failedCount;
} MORPH_RESULT;

// Modüldeki tüm bilinen prologue'ları dönüştür
MORPH_RESULT morph_all_prologues(PVOID moduleBase, DWORD moduleSize)
{
    MORPH_RESULT result = {moduleBase, moduleSize, 0, 0};

    BYTE *base = (BYTE *)moduleBase;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

    // Sadece .text section'ını tara
    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
        if (!(sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE *secBase = base + sections[s].VirtualAddress;
        DWORD secSize = sections[s].Misc.VirtualSize;

        DWORD oldProt;
        VirtualProtect(secBase, secSize, PAGE_EXECUTE_READWRITE, &oldProt);

        // Her byte'ı kontrol et
        for (DWORD i = 0; i < secSize - 16; i++) {
            for (int p = 0; p < (int)NUM_PROLOGUES; p++) {
                if (!match_pattern(secBase + i, &g_known_prologues[p]))
                    continue;

                // Eşleşme bulundu — morph et
                // Strateji 1: Basit substitution (yerinde, boyut aynı)
                int pLen = g_known_prologues[p].length;

                // En güvenli: sadece alternatif encoding
                // 55 → aynı kalır (push ebp değiştirilemez, 1 byte)
                // 8B EC → 89 E5 (mov ebp, esp alternatif)
                if (pLen >= 3 && secBase[i] == 0x55 &&
                    secBase[i+1] == 0x8B && secBase[i+2] == 0xEC) {
                    secBase[i+1] = 0x89;
                    secBase[i+2] = 0xE5;
                    result.morphedCount++;
                }

                // sub esp, imm8 → farklı encoding yok ama
                // imm8'i imm32'ye genişletebiliriz (5 byte → 6 byte)
                // Bu boyut değiştireceği için riskli — sadece encoding swap yap

                break;
            }
        }

        VirtualProtect(secBase, secSize, oldProt, &oldProt);
    }

    return result;
}

// Tek bir fonksiyonun prologunu morph et (güvenli, boyut koruyarak)
BOOL morph_single_function(PVOID funcAddr, int prologueSize)
{
    BYTE *func = (BYTE *)funcAddr;
    DWORD oldProt;

    if (!VirtualProtect(func, prologueSize, PAGE_EXECUTE_READWRITE, &oldProt))
        return FALSE;

    // "push ebp; mov ebp, esp" → "push ebp; mov ebp, esp" (alternatif encoding)
    // 55 8B EC → 55 89 E5
    if (func[0] == 0x55 && func[1] == 0x8B && func[2] == 0xEC) {
        func[1] = 0x89;
        func[2] = 0xE5;
    }

    // "mov edi, edi" (hotpatch) → "xchg eax, eax" (2-byte NOP alternatifi)
    // 8B FF → 87 C0
    if (func[0] == 0x8B && func[1] == 0xFF) {
        func[0] = 0x87;
        func[1] = 0xC0;
    }

    VirtualProtect(func, prologueSize, oldProt, &oldProt);
    return TRUE;
}
