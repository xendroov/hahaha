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

all: $(OUTDIR) injector payload

$(OUTDIR):
	@if not exist $(OUTDIR) mkdir $(OUTDIR)

# --- Injector EXE ---
injector: $(OUTDIR)
	$(CC) $(CFLAGS) /Fe:$(OUTDIR)\injector.exe injector\injector.c \
		/link $(LDFLAGS) kernel32.lib advapi32.lib

# --- Payload DLL ---
PAYLOAD_SRCS = payload\main.c payload\log.c payload\syscall.c \
               payload\antisig.c payload\stealth.c payload\xmon.c \
               payload\pcap.c payload\gstate.c

PAYLOAD_OBJS = $(OUTDIR)\main.obj $(OUTDIR)\log.obj $(OUTDIR)\syscall.obj \
               $(OUTDIR)\antisig.obj $(OUTDIR)\stealth.obj $(OUTDIR)\xmon.obj \
               $(OUTDIR)\pcap.obj $(OUTDIR)\gstate.obj

payload: $(OUTDIR) $(PAYLOAD_OBJS)
	$(LINK) $(LDFLAGS) /DLL /OUT:$(OUTDIR)\payload.dll $(PAYLOAD_OBJS) \
		kernel32.lib user32.lib advapi32.lib

{payload\}.c{$(OUTDIR)\}.obj:
	$(CC) $(CFLAGS) /c /Fo$@ $<

clean:
	@if exist $(OUTDIR) rmdir /s /q $(OUTDIR)
