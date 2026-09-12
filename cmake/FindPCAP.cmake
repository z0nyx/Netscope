#[=======================================================================[.rst:
FindPCAP
--------

Locates libpcap, which does not ship a standard CMake config on most
distributions.

Result variables:

``PCAP_FOUND``
  True if libpcap headers and library were found.
``PCAP_INCLUDE_DIRS``
  Directory containing ``pcap.h``.
``PCAP_LIBRARIES``
  Libraries to link against.

Imported target:

``PCAP::PCAP``
#]=======================================================================]

find_path(PCAP_INCLUDE_DIR NAMES pcap.h pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
)

if(PCAP_FOUND)
    set(PCAP_INCLUDE_DIRS "${PCAP_INCLUDE_DIR}")
    set(PCAP_LIBRARIES "${PCAP_LIBRARY}")

    if(NOT TARGET PCAP::PCAP)
        add_library(PCAP::PCAP UNKNOWN IMPORTED)
        set_target_properties(PCAP::PCAP PROPERTIES
            IMPORTED_LOCATION "${PCAP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
