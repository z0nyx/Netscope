# Optional sanitizer instrumentation for debugging/CI, never enabled by default.

add_library(netscope_sanitizers INTERFACE)

if(NETSCOPE_ENABLE_ASAN OR NETSCOPE_ENABLE_UBSAN)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        message(WARNING "Sanitizers requested but compiler is not GCC/Clang; ignoring.")
    else()
        set(_netscope_sanitizer_list "")
        if(NETSCOPE_ENABLE_ASAN)
            list(APPEND _netscope_sanitizer_list "address" "undefined" "leak")
        endif()
        if(NETSCOPE_ENABLE_UBSAN)
            list(APPEND _netscope_sanitizer_list "undefined")
        endif()
        list(REMOVE_DUPLICATES _netscope_sanitizer_list)
        string(REPLACE ";" "," _netscope_sanitizer_csv "${_netscope_sanitizer_list}")

        target_compile_options(netscope_sanitizers INTERFACE
            -fsanitize=${_netscope_sanitizer_csv}
            -fno-omit-frame-pointer
            -fno-sanitize-recover=all
        )
        target_link_options(netscope_sanitizers INTERFACE
            -fsanitize=${_netscope_sanitizer_csv}
        )
    endif()
endif()
