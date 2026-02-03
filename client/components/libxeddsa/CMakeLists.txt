cmake_minimum_required(VERSION 3.20)
# 1. Define the source files for the xeddsa library
set(xeddsa_sources
    src/ed25519.c
    src/pub_conversion.c
    src/pub_derivation.c
    src/seed_priv_utils.c
    src/utils.c
    src/version.c
    src/x25519.c
    src/xeddsa.c
)

# 2. Register this directory as an ESP-IDF component
idf_component_register(
    SRCS "${xeddsa_sources}"
    INCLUDE_DIRS "include" "ref10/include"
    PRIV_REQUIRES "espressif__libsodium"
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-error=unused-function" "-Wno-error=parentheses")

# 3. Add the 'ref10' subdirectory, which builds the crypto primitives.
add_subdirectory(ref10)

# 4. Add private include directories needed by the component's sources.
#    (${COMPONENT_LIB} is a variable created by idf_component_register)
target_include_directories(${COMPONENT_LIB} PRIVATE
    "ref10/crypto_sign"
    "ref10/crypto_hash"
    "ref10/crypto_hashblocks"
    "ref10/crypto_verify"
    "ref10/fastrandombytes"
    "ref10/crypto_rng"
    "ref10/crypto_stream"
    "ref10/crypto_core"
    "ref10/kernelrandombytes"
)

# 5. Add compile definitions needed for the build.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    BUILD
    SODIUM_DLL_EXPORT
)

# 6. Link the component library against the *static* libraries built by 'ref10'.
target_link_libraries(${COMPONENT_LIB} PRIVATE
    crypto_sign_static
    crypto_hash_static
    crypto_hashblocks_static
    crypto_verify_static
    fastrandombytes_static
    crypto_rng_static
    crypto_stream_static
    crypto_core_static
    kernelrandombytes_static
)