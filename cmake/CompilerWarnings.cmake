# Shared warning flags for NetScope's own targets.
# Kept out of global CMAKE_C_FLAGS so third-party code (if ever vendored) is unaffected.

add_library(netscope_warnings INTERFACE)

set(_netscope_warning_flags
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wformat=2
    -Wundef
    -Wcast-qual
    -Wpointer-arith
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(netscope_warnings INTERFACE ${_netscope_warning_flags})
endif()

if(NETSCOPE_WARNINGS_AS_ERRORS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(netscope_warnings INTERFACE -Werror)
    endif()
endif()
