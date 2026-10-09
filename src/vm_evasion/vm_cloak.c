// VM Evasion: XIGNCODE VM Policy Bypass
//
// XIGNCODE policy'leri:
//   SMOD.VM, SMOD.VM.Vmware.E/F, SMOD.VM.VMni.VBox.ProcId,
//   CMOD.HighCodeDensityVmWndC, TOOL.Gen.Virtualbattery, vb.
//
// XIGNCODE VM tespiti çok katmanlı:
//   1. CPUID leaf 0x40000000 — hypervisor vendor string
//   2. SMBIOS/ACPI tabloları — NtQuerySystemInformation class=0x4C
//   3. Registry anahtarları — VMware/VBox keys
//   4. MAC adresi OUI — VMware (00:0C:29), VBox (08:00:27)
//   5. Dosya/driver isimleri — vboxguest.sys, vmhgfs.sys, vmmouse.sys
//   6. Process isimleri — vmtoolsd.exe, VBoxService.exe
//   7. Window class isimleri — VBoxTrayToolWndClass
//   8. WMI sorguları — Win32_ComputerSystem.Model
//   9. I/O port — VMware backdoor (in eax, dx; port 0x5658)
//  10. Timing — RDTSC delta (VM overhead)
//
// Bu modül bunları user-mode'dan atlatır (kernel driver gerektirmez).
// Her tespit vektörü için ayrı bypass.

#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")

// ===================================================================
// 1. Registry Cloaking — VM anahtarlarını gizle
//
// XIGNCODE RegOpenKeyEx/RegQueryValueEx ile şunları kontrol eder:
//   HKLM\SOFTWARE\VMware, Inc.\VMware Tools
//   HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
//   HKLM\SYSTEM\CurrentControlSet\Enum\PCI (VMware/VBox device IDs)
//   HKLM\HARDWARE\ACPI\DSDT\VBOX__
//
// Hook yaklaşımı: NtOpenKey/NtQueryValueKey hook ile
// bu anahtarlara erişimi STATUS_OBJECT_NAME_NOT_FOUND döndür
// ===================================================================

typedef struct {
    const wchar_t *keyFragment; // Registry yolundaki anahtar kelime
} VM_REGISTRY_ENTRY;

static VM_REGISTRY_ENTRY g_vm_reg_entries[] = {
    { L"VMware" },
    { L"VirtualBox" },
    { L"VBOX__" },
    { L"Virtual Machine" },
    { L"QEMU" },
    { L"Hyper-V" },
    { L"Parallels" },
    { NULL }
};

// Registry hook callback — VEH veya IAT hook ile çağrılır
// keyPath VM imzası içeriyorsa STATUS_OBJECT_NAME_NOT_FOUND döndür
BOOL should_hide_registry_key(const wchar_t *keyPath)
{
    if (!keyPath) return FALSE;

    for (int i = 0; g_vm_reg_entries[i].keyFragment; i++) {
        if (wcsstr(keyPath, g_vm_reg_entries[i].keyFragment) != NULL)
            return TRUE;
    }
    return FALSE;
}

// ===================================================================
// 2. MAC Address Spoofing
//
// XIGNCODE GetAdaptersInfo/GetAdaptersAddresses ile MAC'i okur
// VMware: 00:0C:29:xx:xx:xx veya 00:50:56:xx:xx:xx
// VBox:   08:00:27:xx:xx:xx
// QEMU:   52:54:00:xx:xx:xx
//
// Registry'den MAC değiştirmek en temiz yol:
//   HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972...}\000x
//   NetworkAddress = "001122334455"
//
// Veya runtime'da GetAdaptersInfo hook'u
// ===================================================================

typedef struct {
    BYTE prefix[3];
    const char *vendor;
} VM_MAC_PREFIX;

static VM_MAC_PREFIX g_vm_macs[] = {
    { {0x00, 0x0C, 0x29}, "VMware" },
    { {0x00, 0x50, 0x56}, "VMware" },
    { {0x08, 0x00, 0x27}, "VirtualBox" },
    { {0x52, 0x54, 0x00}, "QEMU" },
    { {0x00, 0x15, 0x5D}, "Hyper-V" },
    { {0x00, 0x1C, 0x42}, "Parallels" },
};

#define NUM_VM_MACS (sizeof(g_vm_macs) / sizeof(g_vm_macs[0]))

BOOL is_vm_mac(const BYTE *mac)
{
    for (int i = 0; i < (int)NUM_VM_MACS; i++) {
        if (memcmp(mac, g_vm_macs[i].prefix, 3) == 0)
            return TRUE;
    }
    return FALSE;
}

// Gerçek fiziksel bir MAC adresi üret (Intel OUI kullan)
void generate_physical_mac(BYTE *out)
{
    // Intel OUI prefix'leri (en yaygın fiziksel NIC üreticisi)
    BYTE intelOUIs[][3] = {
        {0x3C, 0x97, 0x0E}, // Intel Corporation
        {0x48, 0x21, 0x0B}, // Intel Corporate
        {0xA4, 0xBF, 0x01}, // Intel Corporate
        {0xD4, 0x5D, 0x64}, // Intel Corporate
        {0x80, 0x86, 0xF2}, // Intel Corporate
    };

    DWORD seed = GetTickCount() ^ GetCurrentProcessId();
    int ouiIdx = seed % (sizeof(intelOUIs) / sizeof(intelOUIs[0]));

    memcpy(out, intelOUIs[ouiIdx], 3);

    // Son 3 byte rastgele
    seed = seed * 1103515245 + 12345;
    out[3] = (BYTE)(seed >> 16);
    seed = seed * 1103515245 + 12345;
    out[4] = (BYTE)(seed >> 16);
    seed = seed * 1103515245 + 12345;
    out[5] = (BYTE)(seed >> 16);
}

// ===================================================================
// 3. SMBIOS/ACPI Tablosu Maskeleme
//
// XIGNCODE NtQuerySystemInformation(0x4C) ile firmware tabloları okur.
// (v5 dump: xcorona.xem 0x2BCA6CC3 caller, VMProtect'ten)
//
// SMBIOS Type 1 (System Information):
//   Manufacturer: "VMware, Inc." → "Dell Inc."
//   ProductName: "VMware Virtual Platform" → "Latitude 5520"
//   SerialNumber: "VMware-xx" → rastgele
//
// Hook: NtQuerySystemInformation(SystemFirmwareTableInformation)
//       return buffer'ındaki string'leri değiştir
// ===================================================================

typedef struct {
    const char *vmString;
    const char *replacement;
} SMBIOS_REPLACE;

static SMBIOS_REPLACE g_smbios_replacements[] = {
    { "VMware, Inc.",               "Dell Inc." },
    { "VMware Virtual Platform",    "Latitude 5520" },
    { "VMware",                     "Dell" },
    { "Virtual Machine",            "Latitude 5520" },
    { "VBOX",                       "Dell" },
    { "VirtualBox",                 "Latitude 5520" },
    { "Oracle Corporation",         "Dell Inc." },
    { "innotek GmbH",              "Dell Inc." },
    { "QEMU",                       "Dell" },
    { "Bochs",                      "Dell" },
    { NULL, NULL }
};

// SMBIOS buffer'ındaki VM string'lerini değiştir
void patch_smbios_buffer(BYTE *buf, DWORD bufSize)
{
    for (int i = 0; g_smbios_replacements[i].vmString; i++) {
        const char *search = g_smbios_replacements[i].vmString;
        const char *replace = g_smbios_replacements[i].replacement;
        int searchLen = (int)strlen(search);
        int replaceLen = (int)strlen(replace);

        for (DWORD pos = 0; pos + searchLen <= bufSize; pos++) {
            if (memcmp(buf + pos, search, searchLen) == 0) {
                // Yerinde değiştir (replace kısa veya eşitse)
                if (replaceLen <= searchLen) {
                    memcpy(buf + pos, replace, replaceLen);
                    // Kalan byte'ları boşlukla doldur
                    memset(buf + pos + replaceLen, ' ', searchLen - replaceLen);
                }
            }
        }
    }
}

// ===================================================================
// 4. VM Process/Service Gizleme
//
// XIGNCODE process taramasında şunları arar:
//   vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe
//   VBoxService.exe, VBoxTray.exe
//   qemu-ga.exe
//
// Çözüm: VM araçlarını durdurmak yerine, process listesini
// hook'layarak gizlemek (NtQuerySystemInformation hook)
// ===================================================================

static const char *g_vm_processes[] = {
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
    "vmacthlp.exe", "vmware-vmx.exe",
    "VBoxService.exe", "VBoxTray.exe",
    "qemu-ga.exe",
    "prl_tools.exe", "prl_cc.exe",
    NULL
};

BOOL is_vm_process(const char *processName)
{
    for (int i = 0; g_vm_processes[i]; i++) {
        if (_stricmp(processName, g_vm_processes[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// ===================================================================
// 5. VM Driver/File Gizleme
//
// XIGNCODE dosya sistemi ve driver taramasında:
//   C:\Windows\System32\drivers\vmmouse.sys
//   C:\Windows\System32\drivers\vmhgfs.sys
//   C:\Windows\System32\drivers\VBoxMouse.sys
//   C:\Windows\System32\drivers\VBoxGuest.sys
//   C:\Program Files\VMware\VMware Tools\
//   C:\Program Files\Oracle\VirtualBox Guest Additions\
// ===================================================================

static const wchar_t *g_vm_files[] = {
    L"vmmouse.sys", L"vmhgfs.sys", L"vmsrvc.sys", L"vmci.sys",
    L"vmx_svga.sys", L"vm3dmp.sys",
    L"VBoxMouse.sys", L"VBoxGuest.sys", L"VBoxSF.sys",
    L"VBoxVideo.sys",
    L"vioscsi.sys", L"viostor.sys", // Virtio (QEMU/KVM)
    NULL
};

BOOL is_vm_file(const wchar_t *fileName)
{
    for (int i = 0; g_vm_files[i]; i++) {
        if (wcsstr(fileName, g_vm_files[i]) != NULL)
            return TRUE;
    }
    return FALSE;
}

// ===================================================================
// 6. CPUID Maskeleme (user-mode)
//
// CPUID leaf 0x40000000: hypervisor brand string
//   VMware: "VMwareVMware"
//   VBox:   "VBoxVBoxVBox"
//   Hyper-V: "Microsoft Hv"
//   KVM:    "KVMKVMKVM"
//
// CPUID leaf 1, ECX bit 31: hypervisor present flag
//
// User-mode'dan CPUID'yi doğrudan değiştiremeyiz.
// Ama __cpuid() çağrılarını hook'layabiliriz:
//   - XIGNCODE __cpuid'yi dolaylı çağırıyorsa (function call)
//     → o fonksiyonu hook'la
//   - Doğrudan CPUID instruction'ı çalıştırıyorsa
//     → yalnızca hypervisor/kernel driver ile çözülebilir (Level 3-4)
//
// Pragmatik yaklaşım: VMProtect'in .vlizer section'ında CPUID
// çağrısını bulmak ve NOP'lamak (statik patch, çok riskli)
// ===================================================================

// CPUID sonucunu "fiziksel" görünecek şekilde düzelt
void fix_cpuid_result(int leaf, int *eax, int *ebx, int *ecx, int *edx)
{
    if (leaf == 0x40000000) {
        // Hypervisor yok gibi göster
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
    }
    if (leaf == 1) {
        // Bit 31 temizle (hypervisor present flag)
        *ecx &= ~(1 << 31);
    }
}

// ===================================================================
// 7. Timing Anti-Detection
//
// VM'de RDTSC delta normalde daha yüksek (VM-Exit overhead).
// XIGNCODE bunu ölçebilir.
//
// User-mode çözüm: QueryPerformanceCounter / GetTickCount64 hook
// ile tutarlı değerler döndürmek.
// Kernel çözüm: TSC offset ayarlama (Level 3-4)
// ===================================================================

static LARGE_INTEGER g_timing_offset = {0};
static BOOL g_timing_initialized = FALSE;

void init_timing_compensation(void)
{
    // İlk çağrıda referans farkını hesapla
    // VM overhead'ini kompanse etmek için offset tut
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    // Bilinen bir süre bekle
    Sleep(1);

    QueryPerformanceCounter(&end);

    // 1ms için beklenen tick sayısı
    LONGLONG expected = freq.QuadPart / 1000;
    LONGLONG actual = end.QuadPart - start.QuadPart;

    // Fark VM overhead'i
    g_timing_offset.QuadPart = actual - expected;
    g_timing_initialized = TRUE;
}

// ===================================================================
// Ana VM Cloaking Fonksiyonu
// ===================================================================

typedef struct {
    BOOL registryCloaked;
    BOOL macSpoofed;
    BOOL smbiosPatched;
    BOOL processesHidden;
    BOOL timingCompensated;
    int detectedVM; // 0=yok, 1=VMware, 2=VBox, 3=QEMU, 4=Hyper-V
} VM_CLOAK_STATUS;

VM_CLOAK_STATUS vm_cloak_init(void)
{
    VM_CLOAK_STATUS status = {0};

    // VM tespiti yap (bypass'tan önce ne ile karşı karşıya olduğumuzu bilelim)
    int cpuid_result[4];
    __cpuid(cpuid_result, 0x40000000);

    char vendor[13] = {0};
    memcpy(vendor + 0, &cpuid_result[1], 4); // EBX
    memcpy(vendor + 4, &cpuid_result[2], 4); // ECX
    memcpy(vendor + 8, &cpuid_result[3], 4); // EDX

    if (strstr(vendor, "VMware"))     status.detectedVM = 1;
    else if (strstr(vendor, "VBox"))  status.detectedVM = 2;
    else if (strstr(vendor, "KVM"))   status.detectedVM = 3;
    else if (strstr(vendor, "Micro")) status.detectedVM = 4;

    // Timing compensation (her zaman çalıştır)
    init_timing_compensation();
    status.timingCompensated = TRUE;

    return status;
}
