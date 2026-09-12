cmake_minimum_required(VERSION 3.20)
project(netscope
    VERSION 0.1.0
    DESCRIPTION "Network traffic analyzer"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(NETSCOPE_ENABLE_ASAN "Build with AddressSanitizer + LeakSanitizer" OFF)
option(NETSCOPE_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer" OFF)
option(NETSCOPE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(NETSCOPE_BUILD_TESTS "Build the test suite" ON)

include(CompilerWarnings)
include(Sanitizers)

find_package(PCAP)
if(NOT PCAP_FOUND)
    message(WARNING
        "libpcap was not found. The 'netscope_core' parsing library and its "
        "tests will still build, but the 'netscope' capture executable "
        "will be skipped. Install libpcap (or libpcap-dev / Npcap SDK) and "
        "re-run cmake to build the full application."
    )
endif()

# --- netscope_core: protocol parsing, packet model, filters, stats, output.
# Deliberately independent of libpcap so it can be built, tested, and fuzzed
# on any platform/toolchain without a live capture backend. See
# docs/architecture.md for the rationale.

add_library(netscope_core STATIC
    src/packet.c
    src/config.c
    src/filter.c
    src/stats.c
    src/output.c
    src/util.c
    src/log.c
    src/protocols/ethernet.c
    src/protocols/arp.c
    src/protocols/ipv4.c
    src/protocols/ipv6.c
    src/protocols/tcp.c
    src/protocols/udp.c
    src/protocols/icmp.c
    src/protocols/icmpv6.c
    src/protocols/dns.c
)

target_include_directories(netscope_core PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries(netscope_core PUBLIC netscope_warnings netscope_sanitizers)

# --- netscope: the CLI application. Requires libpcap for live capture and
# offline pcap file I/O.

if(PCAP_FOUND)
    add_executable(netscope
        src/main.c
        src/capture.c
        src/signal_handler.c
    )
    target_link_libraries(netscope PRIVATE netscope_core PCAP::PCAP)
endif()

if(NETSCOPE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
