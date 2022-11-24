# Aleth: Ethereum C++ client, tools and libraries.
# Copyright 2013-2019 Aleth Authors.
# Licensed under the GNU General Public License, Version 3. See the LICENSE file.

cmake_minimum_required(VERSION 3.9.3)

#if(WIN32)
# HC: remove /MDd
#set(CMAKE_CXX_FLAGS_DEBUG "")
#endif()

#HC: already contained
#if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/evmc/.git OR NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cable/.git)
#    message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init")
#endif()

# HC: solved the conflict with HC
if(EXISTS "${CMAKE_TOOLCHAIN_FILE}")
	message(STATUS "CMAKE_TOOLCHAIN_FILE is : ${CMAKE_TOOLCHAIN_FILE}, in order to avoid conflict with other project, clean it...")
	set(CMAKE_TOOLCHAIN_FILE "")
endif()


include(cmake/cable/bootstrap.cmake)
include(CableBuildInfo)
include(CableBuildType)
include(CableToolchains)
include(GNUInstallDirs)

cable_configure_toolchain(DEFAULT cxx14-pic)

#HC:
message(STATUS "CMAKE_TOOLCHAIN_FILE is : ${CMAKE_TOOLCHAIN_FILE}")


# HC: fix the issue like: relocation R_X86_64_32 against `.rodata' can not be used when making a shared object; recompile with -fPIC
if (("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU") OR ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)
	SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fPIC")
	SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
	message(STATUS "**************** CMAKE_POSITION_INDEPENDENT_CODE: ${CMAKE_POSITION_INDEPENDENT_CODE} ************")
endif()

set(ETH_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${ETH_CMAKE_DIR})

# HC: comment the following codes for compiling Debug version
if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
	# Map current configuration to configurations of imported targets.
	set(CMAKE_MAP_IMPORTED_CONFIG_DEBUG Release)
	set(CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release)
endif()


#HC: remove the define of PROJECT_NAME, otherwise Hunter will run into error
set(PROJECT_NAME)

#HC: debug option
set(HUNTER_STATUS_DEBUG 1)

#HC:
if(WIN32)
    if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(HUNTER_CONFIGURATION_TYPES Debug CACHE STRING "Hunter configuration types")
    else()
        set(HUNTER_CONFIGURATION_TYPES Release CACHE STRING "Hunter configuration types")
    endif()
else()
    # HC: Outside of Windows build only Release packages.
    set(HUNTER_CONFIGURATION_TYPES Release
        CACHE STRING "Build type of the Hunter packages")
endif()

message(STATUS "**************** CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE} ************")


set(HUNTER_JOBS_NUMBER 4 CACHE STRING "Hunter jobs number")
set(HUNTER_CACHE_SERVERS "https://github.com/ethereum/hunter-cache" CACHE STRING "Hunter cache servers")
set(HUNTER_PASSWORDS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/passwords.cmake CACHE STRING "Hunter password path")

# In CI builds upload the binaries if the GITHUB_USER_PASSWORD was decrypted
# (only for branches and internal PRs).
if("$ENV{CI}" AND NOT "$ENV{GITHUB_USER_PASSWORD}" STREQUAL "")
    set(run_upload YES)
else()
    set(run_upload NO)
endif()
option(HUNTER_RUN_UPLOAD "Upload binaries to the cache server" ${run_upload})

include(HunterGate)
HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.23.211.tar.gz"
    SHA1 "c022f0c2480e835a6bafdd734035ec2071b51897"
    LOCAL
)

#HC: about macro cable_set_build_type, more see eth\cmake\cable\CableBuildType.cmake
cable_set_build_type(DEFAULT RelWithDebInfo CONFIGURATION_TYPES Debug;Release;RelWithDebInfo)

project(aleth)
set(PROJECT_VERSION 1.8.0)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
if(NOT WIN32)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

cable_add_buildinfo_library(PROJECT_NAME aleth)

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY On)

include(EthCcache)
include(EthOptions)
include(EthCompilerSettings)
include(EthExecutableHelper)
include(EthDependencies)
include(EthUtils)

#set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
ADD_DEFINITIONS(-DBOOST_LOG_DYN_LINK)
#hunter_add_package(Boost COMPONENTS program_options filesystem system thread context fiber log)
#find_package(Boost CONFIG REQUIRED program_options filesystem system thread context fiber log)
#find_package(Boost REQUIRED COMPONENTS program_options filesystem system thread context fiber log)

message(STATUS "*********** ${Boost_INCLUDE_DIR} ************")

hunter_add_package(jsoncpp)
find_package(jsoncpp CONFIG REQUIRED)

hunter_add_package(Snappy)
find_package(Snappy CONFIG REQUIRED)
if(Snappy_NOFOUND)
    message(STATUS "NOFound Snappy")
endif()

if(snappy_FOUND)
    message(STATUS "Found snappy ${Snappy_LIBRARY} : ${Snappy_LIBRARIES}")
else()
	message(STATUS "NOFound snappy")
endif()

get_target_property ( VAR1 Snappy::snappy IMPORTED_LOCATION_DEBUG)


hunter_add_package(cryptopp)
find_package(cryptopp CONFIG REQUIRED)

hunter_add_package(libjson-rpc-cpp)
find_package(libjson-rpc-cpp CONFIG REQUIRED)

hunter_add_package(libscrypt)
find_package(libscrypt CONFIG REQUIRED)

hunter_add_package(ethash)
find_package(ethash CONFIG REQUIRED)

message("Crypto++: ${HUNTER_cryptopp_VERSION}")

include(ProjectSecp256k1)
include(ProjectLibFF)

find_package(Threads)

if(MINIUPNPC)
    find_package(Miniupnpc 1.8.2013 REQUIRED)
endif()

set(UTILS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/utils")

configure_project()

if(TESTS)
    # Import binaryen library for testeth.
    # TODO: remove this once testeth uses binaryen as a CLI tool.
    include(ProjectBinaryen)
endif()

add_subdirectory(evmc)

#Global include path for all libs.

#HC: Replace CMAKE_SOURCE_DIR with CMAKE_CURRENT_SOURCE_DIR
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

option(ALETH_INTERPRETER_SHARED "Build aleth-interpreter as a shared library" OFF)
add_subdirectory(libaleth-interpreter)

add_subdirectory(libdevcore)
add_subdirectory(libdevcrypto)
add_subdirectory(libp2p)

add_subdirectory(libethcore)
add_subdirectory(libevm)
add_subdirectory(libethereum)
add_subdirectory(libethashseal)

add_subdirectory(libwebthree)
add_subdirectory(libweb3jsonrpc)

add_subdirectory(aleth)

if (TOOLS)
    add_subdirectory(aleth-key)
    add_subdirectory(aleth-vm)
    add_subdirectory(rlp)
    add_subdirectory(aleth-bootnode)
endif()

if (TESTS)
    enable_testing()
    #HC:
    #add_subdirectory(test)
endif()


install(FILES ${PROJECT_BINARY_DIR}/aleth/buildinfo.json DESTINATION ${CMAKE_INSTALL_DATADIR}/aleth)


if(WIN32)
    set(CPACK_GENERATOR ZIP)
else()
    set(CPACK_GENERATOR TGZ)
endif()
set(CPACK_PACKAGE_FILE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_CHECKSUM SHA256)
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY FALSE)
include(CPack)
