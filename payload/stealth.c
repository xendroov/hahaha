#include <windows.h>
#include <string.h>

/*
 * PEB unlinking + PE header wipe
 *
 * XIGNCODE3 xmag.xem ~2 dakikada bir modul listesini tariyorabilir.
 * DLL yuklenir yuklenmez kendimizi PEB'den cikarirsak,
 * tarama bizi bulamaz.
 *
 * 1) PEB_LDR_DATA'daki uc modul listesinden unlink
 * 2) PE header'i (MZ/PE signature) sifirla
 * 3) DLL adi stringlerini temizle
 */

/* LIST_ENTRY unlink helper */
static void unlink(LIST_ENTRY *e)
{
    e->Blink->Flink = e->Flink;
    e->Flink->Blink = e->Blink;
    e->Flink = e;
    e->Blink = e;
}

void stealth_hide(HMODULE hMod)
{
    /*
     * x86 PEB layout:
     *   fs:[0x30]             → PEB
     *   PEB + 0x0C            → PEB_LDR_DATA*
     *   LDR + 0x0C            → InLoadOrderModuleList (LIST_ENTRY head)
     *   LDR + 0x14            → InMemoryOrderModuleList
     *   LDR + 0x1C            → InInitializationOrderModuleList
     *
     * LDR_DATA_TABLE_ENTRY:
     *   +0x00  InLoadOrderLinks
     *   +0x08  InMemoryOrderLinks
     *   +0x10  InInitializationOrderLinks
     *   +0x18  DllBase
     *   +0x20  SizeOfImage
     *   +0x24  FullDllName (UNICODE_STRING)
     *   +0x2C  BaseDllName (UNICODE_STRING)
     */

    DWORD pebAddr;
    __asm {
        mov eax, dword ptr fs:[0x30]
        mov pebAddr, eax
    }

    DWORD ldrAddr = *(DWORD *)(pebAddr + 0x0C);
    LIST_ENTRY *head = (LIST_ENTRY *)(ldrAddr + 0x0C);
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        PVOID dllBase = *(PVOID *)((BYTE *)cur + 0x18);

        if (dllBase == (PVOID)hMod) {
            LIST_ENTRY *memLinks  = (LIST_ENTRY *)((BYTE *)cur + 0x08);
            LIST_ENTRY *initLinks = (LIST_ENTRY *)((BYTE *)cur + 0x10);

            unlink(cur);
            unlink(memLinks);
            unlink(initLinks);

            /* DLL isim stringlerini temizle */
            /* FullDllName.Buffer at +0x28, Length at +0x24 */
            WORD nameLen = *(WORD *)((BYTE *)cur + 0x24);
            PVOID nameBuf = *(PVOID *)((BYTE *)cur + 0x28);
            if (nameBuf && nameLen)
                memset(nameBuf, 0, nameLen);

            /* BaseDllName.Buffer at +0x30, Length at +0x2C */
            WORD baseLen = *(WORD *)((BYTE *)cur + 0x2C);
            PVOID baseBuf = *(PVOID *)((BYTE *)cur + 0x30);
            if (baseBuf && baseLen)
                memset(baseBuf, 0, baseLen);

            break;
        }
        cur = cur->Flink;
    }

    /* PE header sifirla — MZ/PE signature yok olur */
    DWORD old;
    if (VirtualProtect((PVOID)hMod, 0x1000, PAGE_READWRITE, &old)) {
        memset((PVOID)hMod, 0, 0x1000);
        VirtualProtect((PVOID)hMod, 0x1000, old, &old);
    }
}
