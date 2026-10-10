# Knight Online Pentest Toolkit — MSVC Build
#
# Kullanim:
#   "Developer Command Prompt for VS" ac, proje dizinine git:
#   nmake            — her ikisini derle
#   nmake injector   — sadece injector.exe
#   nmake payload    — sadece payload.dll
#   nmake clean      — temizle
#
# Not: x86 (32-bit) derleyici gerekli. "x86 Native Tools" prompt kullanin.

CC = cl.exe
LINK = link.exe
CFLAGS = /nologo /W3 /O2 /DWIN32 /D_WINDOWS /DUNICODE
LDFLAGS = /nologo /MACHINE:X86

OUTDIR = build

all: $(OUTDIR) injector payload modstom thijack lsp_install lsp_provider

$(OUTDIR):
	@if not exist $(OUTDIR) mkdir $(OUTDIR)

# --- Injector EXE ---
injector: $(OUTDIR)
	$(CC) $(CFLAGS) /Fe:$(OUTDIR)\injector.exe injector\injector.c \
		/link $(LDFLAGS) kernel32.lib advapi32.lib

# --- Payload DLL ---
PAYLOAD_SRCS = payload\main.c payload\log.c payload\syscall.c \
               payload\antisig.c payload\stealth.c payload\xmon.c \
               payload\pcap.c payload\gstate.c payload\forensic.c

PAYLOAD_OBJS = $(OUTDIR)\main.obj $(OUTDIR)\log.obj $(OUTDIR)\syscall.obj \
               $(OUTDIR)\antisig.obj $(OUTDIR)\stealth.obj $(OUTDIR)\xmon.obj \
               $(OUTDIR)\pcap.obj $(OUTDIR)\gstate.obj $(OUTDIR)\forensic.obj

payload: $(OUTDIR) $(PAYLOAD_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$(OUTDIR)\payload.dll $(PAYLOAD_OBJS) \
		kernel32.lib user32.lib advapi32.lib

{payload\}.c{$(OUTDIR)\}.obj:
	$(CC) $(CFLAGS) /c /Fo$@ $<

# --- Module Stomping Injector ---
modstom: $(OUTDIR)
	$(CC) $(CFLAGS) /Fe:$(OUTDIR)\modstom.exe injector\modstom.c \
		/link $(LDFLAGS) kernel32.lib advapi32.lib

# --- Thread Hijack Injector ---
thijack: $(OUTDIR)
	$(CC) $(CFLAGS) /Fe:$(OUTDIR)\thijack.exe injector\thijack.c \
		/link $(LDFLAGS) kernel32.lib advapi32.lib

# --- LSP Installer ---
lsp_install: $(OUTDIR)
	$(CC) $(CFLAGS) /Fe:$(OUTDIR)\lsp_install.exe injector\lsp_install.c \
		/link $(LDFLAGS) ws2_32.lib sporder.lib

# --- LSP Provider DLL ---
lsp_provider: $(OUTDIR)
	$(CC) $(CFLAGS) /Fe:$(OUTDIR)\lsp_provider.dll /LD injector\lsp_provider.c \
		/link $(LDFLAGS) /DLL ws2_32.lib kernel32.lib

clean:
	@if exist $(OUTDIR) rmdir /s /q $(OUTDIR)
