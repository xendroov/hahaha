cmake_minimum_required(VERSION 3.15)
project(ko_pentest C)

# 32-bit zorunlu
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "32-bit (x86) derleyici gerekli! VS'de x86 secin.")
endif()

set(CMAKE_C_STANDARD 11)

# --- Injector EXE ---
add_executable(injector
    injector/injector.c
)
target_link_libraries(injector PRIVATE kernel32 advapi32 user32)

# --- Payload DLL ---
add_library(payload SHARED
    payload/main.c
    payload/log.c
    payload/syscall.c
    payload/antisig.c
    payload/xmon.c
    payload/pcap.c
    payload/gstate.c
    payload/payload.def
)
target_link_libraries(payload PRIVATE kernel32 user32 advapi32)
