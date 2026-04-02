cmake_minimum_required(VERSION 3.16)
project(amanda LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dependencies ──────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)

# libcrystals + transitive deps (for base64_encode/base64_decode)
find_library(CRYSTALS_LIB crystals-1.2 PATHS /usr/local/lib REQUIRED)
find_library(XKCP_LIB     XKCP     PATHS /usr/local/lib REQUIRED)
find_library(BLAKE3_LIB   blake3
    PATHS /mnt/c/Users/daves/OneDrive/Desktop/Crystals/local/lib64 REQUIRED)
find_library(TBB_LIB      tbb
    PATHS /usr/lib64 /mnt/c/Users/daves/OneDrive/Desktop/Crystals/local/lib64 REQUIRED)

set(CRYSTALS_INC /usr/local/include)
set(XKCP_INC /mnt/c/Users/daves/OneDrive/Desktop/Crystals/XKCP/bin/x86-64/libXKCP.so.headers)

# ── fmt (curl emitter) ────────────────────────────────────────────────────────
set(FMT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../fmt)
find_library(FMT_LIB fmt PATHS ${FMT_ROOT}/build REQUIRED)
set(FMT_INC ${FMT_ROOT}/include)

# ── amanda_client (config + HTTP client) ──────────────────────────────────────
add_library(amanda_client STATIC
    config/amanda_config.cpp
    client/client.cpp
)
target_include_directories(amanda_client PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CRYSTALS_INC}
    ${XKCP_INC}
)
target_link_libraries(amanda_client PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    yaml-cpp
    ${CRYSTALS_LIB}
    ${XKCP_LIB}
    ${BLAKE3_LIB}
    ${TBB_LIB}
)
target_compile_options(amanda_client PRIVATE -Wall -Wextra)

# ── amanda executable ─────────────────────────────────────────────────────────
add_executable(amanda
    main.cpp
    cmd/login.cpp
    cmd/users.cpp
    cmd/trays.cpp
    cmd/secrets.cpp
    cmd/tokens.cpp
    cmd/oauth.cpp
    cmd/util.cpp
    cmd/edit.cpp
    cmd/curl_emitter.cpp
    util/editor_util.cpp
)
target_link_libraries(amanda PRIVATE amanda_client ${FMT_LIB})
target_include_directories(amanda PRIVATE ${FMT_INC})
target_compile_options(amanda PRIVATE -Wall -Wextra)

# ── curl emitter tests ────────────────────────────────────────────────────────
add_executable(amanda_curl_test
    cmd/curl_emitter_test.cpp
    cmd/curl_emitter.cpp
)
target_link_libraries(amanda_curl_test PRIVATE amanda_client ${FMT_LIB})
target_include_directories(amanda_curl_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${FMT_INC}
)
target_compile_options(amanda_curl_test PRIVATE -Wall -Wextra)
