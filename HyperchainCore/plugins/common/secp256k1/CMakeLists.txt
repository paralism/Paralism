# Copyright (c) 2017 The Bitcoin developers

cmake_minimum_required(VERSION 3.5)

# HC: change CMAKE_SOURCE_DIR to CMAKE_CURRENT_SOURCE_DIR
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(PROJECT_NAME)

include(HunterGate)

message(STATUS "[project] CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")

option(HUNTER_STATUS_DEBUG "Hunter debug info" ON)
HunterGate(
    URL "https://github.com/ruslo/hunter/archive/refs/tags/v0.23.165.tar.gz"
    SHA1 "5a73f91df5f6109c0bb1104d0c0ee423f7bece79"
    LOCAL
)

set(HUNTER_KEEP_PACKAGE_SOURCES ON)

# HC: secp256k1-lp used by modules of Paracoin and Ledger
# HC: eth has module named as secp256k1
project(secp256k1-lp VERSION 0.3)

include(CTest)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/")
include(AddCompilerFlags)

# libsecp256k1 use a different set of flags.
add_compiler_flag(
	-pedantic
	-Wshadow
	-Wno-unused-function
	-Wno-nonnull
	-Wno-overlength-strings
)

add_c_compiler_flag(
	-std=c89
	-Wno-long-long
)

# Default visibility is hidden on all targets.
set(CMAKE_C_VISIBILITY_PRESET hidden)

# The library

#HC
#set_property(DIRECTORY . PROPERTY INCLUDE_DIRECTORIES "")
#include_directories(${CMAKE_CURRENT_BINARY_DIR}/src)



# HC: module enable
ADD_DEFINITIONS(/DENABLE_MODULE_EXTRAKEYS /DENABLE_MODULE_SCHNORRSIG)
add_library(${PROJECT_NAME} src/secp256k1.c)

# HC:
if(NOT WIN32)
target_compile_options(${PROJECT_NAME} PRIVATE -fPIC)
endif()


# HC use PROJECT_SOURCE_DIR instead of CMAKE_SOURCE_DIR
target_include_directories(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}
	${PROJECT_SOURCE_DIR}/src
	${CMAKE_CURRENT_BINARY_DIR}/src)

if ( WIN32 )
	set(USE_FIELD_10X26 1)
	set(USE_FIELD_INV_BUILTIN 1)
	set(USE_NUM_NONE 1)
	set(USE_SCALAR_8X32 1)
	set(USE_SCALAR_INV_BUILTIN 1)
else ( WIN32 )
	# We need to link in GMP
	find_package(GMP)
	if(GMP_FOUND)
		target_include_directories(${PROJECT_NAME} PUBLIC ${GMP_INCLUDE_DIR})
		target_link_libraries(${PROJECT_NAME} ${GMP_LIBRARY})
		set(USE_NUM_GMP 1)
		set(USE_FIELD_INV_NUM 1)
		set(USE_SCALAR_INV_NUM 1)
	else()
		set(USE_NUM_NONE 1)
		set(USE_FIELD_INV_BUILTIN 1)
		set(USE_SCALAR_INV_BUILTIN 1)
	endif()

	# We check if amd64 asm is supported.
	check_c_source_compiles("
		#include <stdint.h>
		int main() {
			uint64_t a = 11, tmp;
			__asm__ __volatile__(\"movq \$0x100000000,%1; mulq %%rsi\" : \"+a\"(a) : \"S\"(tmp) : \"cc\", \"%rdx\");
			return 0;
		}
	" USE_ASM_X86_64)

	# We make sure __int128 is defined
	include(CheckTypeSize)
	check_type_size(__int128 SIZEOF___INT128)
	if(SIZEOF___INT128 EQUAL 16)
		set(HAVE___INT128 1)
	else()
		# If we do not support __int128, we should be falling back
		# on 32bits implementations for field and scalar.
	endif()

	# Detect if we are on a 32 or 64 bits plateform and chose
	# scalar and filed implementation accordingly
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		# 64 bits implementationr require either __int128 or asm support.
		if (HAVE___INT128 OR USE_ASM_X86_64)
			set(USE_SCALAR_4X64 1)
			set(USE_FIELD_5X52 1)
		else()
			message(SEND_ERROR "Compiler does not support __int128 or insline assembly")
		endif()
	else()
		set(USE_SCALAR_8X32 1)
		set(USE_FIELD_10X26 1)
	endif()
endif ( WIN32 )

# Executable internal to secp256k1 need to have the HAVE_CONFIG_H define set.
# For convenience, we wrap this into a function.
function(link_secp256k1_internal NAME)
	target_link_libraries(${NAME} ${PROJECT_NAME})
	target_compile_definitions(${NAME} PRIVATE HAVE_CONFIG_H SECP256K1_BUILD)
endfunction(link_secp256k1_internal)

# Phony target to build benchmarks
add_custom_target(bench-secp256k1)

function(add_secp256k1_bench NAME)
	add_executable(${NAME} EXCLUDE_FROM_ALL ${ARGN})
	link_secp256k1_internal(${NAME})
	add_dependencies(bench-secp256k1 ${NAME})
endfunction(add_secp256k1_bench)

# ECDH module
option(SECP256K1_ENABLE_MODULE_ECDH "Build libsecp256k1's ECDH module" OFF)
if(SECP256K1_ENABLE_MODULE_ECDH)
	set(ENABLE_MODULE_ECDH 1)
	add_secp256k1_bench(bench_ecdh src/bench_ecdh.c)
endif()

# MultiSet module
option(SECP256K1_ENABLE_MODULE_MULTISET "Build libsecp256k1's MULTISET module" OFF)
if(SECP256K1_ENABLE_MODULE_MULTISET)
    set(ENABLE_MODULE_MULTISET 1)
	add_secp256k1_bench(bench_multiset src/bench_multiset.c)
endif()

# Recovery module
option(SECP256K1_ENABLE_MODULE_RECOVERY "Build libsecp256k1's recovery module" ON)
if(SECP256K1_ENABLE_MODULE_RECOVERY)
	set(ENABLE_MODULE_RECOVERY 1)
	#HC: only enable module, but ignore bench
	#add_secp256k1_bench(bench_recover src/bench_recover.c)
endif()

# Schnorr module
option(SECP256K1_ENABLE_MODULE_SCHNORR "Build libsecp256k1's Schnorr module" ON)
if(SECP256K1_ENABLE_MODULE_SCHNORR)
	set(ENABLE_MODULE_SCHNORR 1)
endif()

# Static precomputation for eliptic curve mutliplication
option(SECP256K1_ECMULT_STATIC_PRECOMPUTATION "Precompute libsecp256k1's eliptic curve mutliplication tables" ON)
if(SECP256K1_ECMULT_STATIC_PRECOMPUTATION)
	set(USE_ECMULT_STATIC_PRECOMPUTATION 1)

	include(NativeExecutable)
	add_native_executable(gen_context src/gen_context.c)
	native_target_include_directories(gen_context PUBLIC . ${CMAKE_CURRENT_BINARY_DIR}/src)

	add_custom_command(
		OUTPUT ecmult_static_context.h
		COMMAND gen_context
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	)

	target_sources(${PROJECT_NAME} PRIVATE ecmult_static_context.h)
endif()

# Generate the config
configure_file(./lib${PROJECT_NAME}-config.h.cmake.in src/lib${PROJECT_NAME}-config.h ESCAPE_QUOTES)
target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_CONFIG_H SECP256K1_BUILD)

# Tests
option(SECP256K1_BUILD_TEST "Build secp256k1's unit tests" OFF)
if(SECP256K1_BUILD_TEST)
	include(TestSuite)
	create_test_suite(${PROJECT_NAME})

	function(create_secp256k1_test NAME FILES)
		add_test_to_suite(${PROJECT_NAME} ${NAME} EXCLUDE_FROM_ALL ${FILES})
		link_secp256k1_internal(${NAME})
	endfunction()

	create_secp256k1_test(tests src/tests.c)
	target_compile_definitions(tests PRIVATE VERIFY)

	create_secp256k1_test(exhaustive_tests src/tests_exhaustive.c)
	# This should not be enabled at the same time as coverage is.
	# TODO: support coverage.
	target_compile_definitions(exhaustive_tests PRIVATE VERIFY)
endif(SECP256K1_BUILD_TEST)

# Benchmarks
#HC: skip
#add_secp256k1_bench(bench_verify src/bench_verify.c)
#add_secp256k1_bench(bench_sign src/bench_sign.c)
#add_secp256k1_bench(bench_internal src/bench_internal.c)



set(pc_config "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc")
configure_file(lib${PROJECT_NAME}.pc.in ${pc_config} @ONLY)

#set(la_config "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.la")
#configure_file(${PROJECT_NAME}.la.in ${la_config} @ONLY)

# Installation (https://github.com/forexample/package-example) {

set(config_install_dir "lib/cmake/${PROJECT_NAME}")
set(include_install_dir "include")

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(namespace "${PROJECT_NAME}::")

include(CMakePackageConfigHelpers)

# Use:
#   * PROJECT_VERSION
write_basic_package_version_file(
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# Use variables:
#   * TARGETS_EXPORT_NAME
#   * PROJECT_NAME
configure_package_config_file(
    "cmake/Config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${config_install_dir}"
)
#HC: don't install
#install(
#    TARGETS ${PROJECT_NAME}
#    EXPORT "${TARGETS_EXPORT_NAME}"
#    LIBRARY DESTINATION "lib"
#    ARCHIVE DESTINATION "lib"
#    RUNTIME DESTINATION "bin"
#    INCLUDES DESTINATION "${include_install_dir}"
#)

#file(GLOB_RECURSE headers include/*.h)

#install(
#    FILES ${headers} ${CMAKE_CURRENT_BINARY_DIR}/src/libsecp256k1-config.h
#    DESTINATION "${include_install_dir}/${PROJECT_NAME}"
#)

#install(
#    FILES "${project_config}" "${version_config}"
#    DESTINATION "${config_install_dir}"
#)

#install(
#    EXPORT "${TARGETS_EXPORT_NAME}"
#    NAMESPACE "${namespace}"
#    DESTINATION "${config_install_dir}"
#)

#install(FILES ${pc_config} DESTINATION lib/pkgconfig)
#install(FILES ${la_config} DESTINATION lib)
