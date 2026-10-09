# XIGNCODE3 Tespit Policy'leri

Penetrasyon testi sırasında keşfedilen Wellbia XIGNCODE3 tespit kuralları.

---

## 1. VM Tespit Policy'leri

| Policy | Hedef |
|--------|-------|
| SMOD.VM | Genel VM tespiti (temel kontrol) |
| SMOD.VM.Vmware.E | VMware ortamı (E varyantı) |
| SMOD.VM.Vmware.F | VMware ortamı (F varyantı) |
| SMOD.VM.VMni.VBox.ProcId | VirtualBox tespiti (WMI Process ID) |
| CMOD.HighCodeDensityVmWndC | Yüksek kod yoğunluğu olan VM pencereleri |
| CMOD.HSuspVirtualMachineVMwareExtraRunning | VMware ekstra çalışan VM'ler |
| TOOL.Gen.Virtualbattery | Sanal batarya araçları |
| TOOL.Hpo.VirtualBattery | HPO sanal batarya araçları |

### Tespit vektörleri (API dump'lardan)
- NtQuerySystemInformation class=0x4C (SystemFirmwareTableInformation)
  - SMBIOS tablosu → üretici adı, seri no, BIOS string'leri
  - ACPI tablosu → VM imzaları
- VBoxHook.dll yükleme tespiti
- WMI sorguları (Win32_ComputerSystem, Win32_BIOS)
- Registry anahtarları (HKLM\SOFTWARE\VMware, VirtualBox)
- MAC adresi OUI kontrolü (VMware: 00:0C:29, VBox: 08:00:27)
- CPUID leaf 0x40000000 (hypervisor vendor string)

---

## 2. Multiclient Policy'leri

| Policy | Hedef |
|--------|-------|
| CMOD.DupClientA | Aynı istemci tekrar bağlantısı |
| CMOD.DupClientB | Çoklu istemci (B varyantı) |
| CMOD.DupClientD | Çoklu istemci (D varyantı) |
| CMOD.MultiClientQ | Çoklu istemci (Q varyantı) |
| CMOD.RoutedClient | Yönlendirilmiş istemci |

### Muhtemel tespit yöntemleri
- Hardware fingerprint karşılaştırması (GetVolumeInformationW, MAC, disk serial)
- Mutex/named pipe kontrolleri (aynı makinede 2. instance)
- Sunucu tarafı IP + HWID eşleştirmesi

---

## 3. Raw Code Detection (KRİTİK)

**Policy: IF.SPIDER RawCodeInjectedB**

Manuel olarak belleğe haritalanan (manual-map) kodu tespit eder.

### Bilinen imzalar
| Değer | Analiz |
|-------|--------|
| `01C10000` | Manual-map image base adresi |
| `01C31D20` | Region içinde örneklenen executable adres |
| `558bec83ec6ca14093e80133c58945fc53565783cffc645d7000` | 32-byte x86 fonksiyon prologu |
| `157c0897dc4` | CRC/hash parmak izi |

### Prologue decode
```
55           push ebp
8B EC        mov ebp, esp
83 EC 6C     sub esp, 0x6C
A1 4093E801  mov eax, [0x01E89340]    ; global değişken (image base'e bağımlı)
33 C5        xor eax, ebp             ; stack cookie XOR
89 45 FC     mov [ebp-4], eax         ; cookie kaydet
53           push ebx
56           push esi
57           push edi
83 CF FC     or edi, 0xFFFFFFFC
C6 45 70 00  mov byte [ebp+0x70], 0   ; lokal değişken init
```

### Tespit mekanizması
1. Bellekteki tüm MEM_PRIVATE + PAGE_EXECUTE* bölgeleri tara
2. Bilinen base adreslerini kontrol et (0x01C10000)
3. Executable bölgelerdeki byte pattern'ları eşleştir
4. Function prologue imzalarını karşılaştır (MSVC derleyici pattern)
5. CRC/hash ile doğrula

### Bypass gereksinimleri
- Rastgele base address (ASLR)
- Function prologue dönüştürme (metamorphic)
- Çalışmayan kod sayfalarını şifrele
- PE header'ı bellekten sil
