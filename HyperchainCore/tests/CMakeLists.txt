cmake_minimum_required(VERSION 3.14)
project(HyperchainCoreTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─────────────────── Google Test ───────────────────
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

# ─────────────────── 项目源码根目录 ───────────────────
get_filename_component(HC_ROOT "${CMAKE_SOURCE_DIR}/.." ABSOLUTE)

# ─────────────────── 全局头文件搜索路径 ───────────────────
include_directories(
    ${HC_ROOT}
    ${HC_ROOT}/headers
    ${HC_ROOT}/node
    ${HC_ROOT}/db
    ${HC_ROOT}/consensus
    ${HC_ROOT}/HyperChain
    ${HC_ROOT}/util
    ${HC_ROOT}/crypto
    ${HC_ROOT}/HttpUnit
    ${HC_ROOT}/thirdparty
    ${CMAKE_SOURCE_DIR}/common
)

find_package(Boost REQUIRED COMPONENTS serialization system filesystem thread)

# ─────────────────── 各模块测试 ───────────────────
add_subdirectory(${HC_ROOT}/headers/tests    ${CMAKE_BINARY_DIR}/headers_tests)
add_subdirectory(${HC_ROOT}/db/tests         ${CMAKE_BINARY_DIR}/db_tests)
add_subdirectory(${HC_ROOT}/HyperChain/tests ${CMAKE_BINARY_DIR}/hyperchain_tests)
add_subdirectory(${HC_ROOT}/consensus/tests  ${CMAKE_BINARY_DIR}/consensus_tests)
add_subdirectory(${HC_ROOT}/node/tests       ${CMAKE_BINARY_DIR}/node_tests)
add_subdirectory(${HC_ROOT}/util/tests       ${CMAKE_BINARY_DIR}/util_tests)
add_subdirectory(${HC_ROOT}/crypto/tests     ${CMAKE_BINARY_DIR}/crypto_tests)
add_subdirectory(${HC_ROOT}/HttpUnit/tests   ${CMAKE_BINARY_DIR}/httpunit_tests)
