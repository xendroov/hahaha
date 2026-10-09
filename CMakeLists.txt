cmake_minimum_required(VERSION 3.15)
project(ko_pentest C)

# 32-bit zorunlu
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "32-bit (x86) derleyici gerekli! VS'de x86 secin.")
endif()

set(CMAKE_C_STANDARD 11)

# --- Injector EXE (opsiyonel, artik d3d9 proxy kullaniliyor) ---
add_executable(injector
    injector/injector.c
)
target_link_libraries(injector PRIVATE kernel32 advapi32 user32)

# --- d3d9.dll — proxy + payload tek dosyada ---
add_library(d3d9_proxy SHARED
    proxy/d3d9.c
    proxy/d3d9.def
    payload/main.c
    payload/log.c
    payload/stealth.c
    payload/syscall.c
    payload/antisig.c
    payload/xmon.c
    payload/pcap.c
    payload/gstate.c
)
set_target_properties(d3d9_proxy PROPERTIES OUTPUT_NAME "d3d9")
target_link_libraries(d3d9_proxy PRIVATE kernel32 user32 advapi32)

# --- dinput8.dll — proxy + payload tek dosyada ---
add_library(dinput8_proxy SHARED
    proxy/dinput8.c
    proxy/dinput8.def
    payload/main.c
    payload/log.c
    payload/stealth.c
    payload/syscall.c
    payload/antisig.c
    payload/xmon.c
    payload/pcap.c
    payload/gstate.c
)
set_target_properties(dinput8_proxy PROPERTIES OUTPUT_NAME "dinput8")
target_link_libraries(dinput8_proxy PRIVATE kernel32 user32 advapi32)

# --- External reader — oyun icine HICBIR SEY enjekte etmez ---
# CreateProcess ile handle alir, ReadProcessMemory ile disaridan okur.
# XIGNCODE'un ObRegisterCallbacks bypass'i: handle driver'dan ONCE alinir.
add_executable(reader
    external/reader.c
)
target_link_libraries(reader PRIVATE kernel32 user32 advapi32)
