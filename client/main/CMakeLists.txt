# main/CMakeLists.txt

# List of all source files in the 'main' component
set(SOURCES
    "app_main.c"
    "x3dh_client.c"
    "common.c"
    "http_client.c"
)

# List of all header include directories
set(INCLUDES
    "."
)

# ESP-IDF macro to register the main component
idf_component_register(
    SRCS "${SOURCES}"
    INCLUDE_DIRS "${INCLUDES}"
    
    # List of components this 'main' component depends on
    REQUIRES
        "libsodium"        # For crypto
        "cjson"            # For JSON parsing
        "esp_wireguard"    # For WireGuard VPN
        
        "mbedtls"          # For kdf
        "nvs_flash"        # For storage
        "esp_wifi"         # For networking
        "esp_netif"        # For networking
        "esp_event"        # For events
        "esp_system"       # For system functions
        "esp_http_client"  # For HTTP

        "libxeddsa"        # For XEdDSA signatures
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-error=pointer-sign")