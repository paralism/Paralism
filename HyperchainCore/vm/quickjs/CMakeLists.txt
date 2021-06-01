cmake_minimum_required(VERSION 3.7)

set(CMAKE_CXX_STANDARD 17)

#project(quickjs LANGUAGES C)
project(quickjs)

file(STRINGS "VERSION" QJS_VERSION_STR)

add_definitions(-DCONFIG_BIGNUM)
add_definitions(-DCONFIG_VERSION="${QJS_VERSION_STR}")


include_directories(${CMAKE_CURRENT_SOURCE_DIR})

#set(LLVM_BUILD_TOOLS on)

if(WIN32)
SET(WIN_HLP_F Win32Console.c Win32Time.cpp)
endif()


set(qjs_cflags -Wall)
if(CMAKE_C_COMPILER_ID MATCHES "AppleClang|Clang")
    list(APPEND qjs_cflags
            -Wextra
            -Wno-sign-compare
            -Wno-missing-field-initializers
            -Wno-unused-parameter
            -Wno-unused-variable
            -funsigned-char)
else()
	#ist(APPEND qjs_cflags -TClang-CL)

    #list(APPEND qjs_cflags
    #        -Wno-array-bounds
    #        -Wno-unused-variable
    #        -Wno-unused-but-set-variable)
endif()

if(UNIX)
add_definitions(-D_GNU_SOURCE=1)
set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
list(APPEND qjs_cflags -Wno-array-bounds -Wno-format-truncation -fPIC)

endif()

#compile qjs and qjsc
if(QJSC)

add_executable(qjsc qjsc.c)
target_link_libraries(qjsc quickjs)

#compile qjscalc.js to qjscalc.c, here we can add more js file to compile.
SET(RESOURCE_COMPILER qjsc)
SET(COMPILING_C "qjscalc")
message(STATUS "qjsc path: " "${RESOURCE_COMPILER}")
FOREACH(INPUT_FILE ${COMPILING_C})
	SET(INPUT_JS_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${INPUT_FILE}.js)
    SET(OUTPUT_FILE ${INPUT_FILE}.c)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${OUTPUT_FILE}
        COMMAND ${RESOURCE_COMPILER} -c -o ${OUTPUT_FILE} ${INPUT_JS_FILE}
        COMMENT "Compiling ${INPUT_JS_FILE} to ${OUTPUT_FILE}")
    LIST(APPEND COMPILED_C ${OUTPUT_FILE})
ENDFOREACH()


add_executable(qjs qjs.c ${COMPILED_C})
target_link_libraries(qjs quickjs dl )

if(UNIX)
target_link_libraries(qjs dl m pthread)
target_link_libraries(qjsc dl m pthread)
endif()

endif() #QJSC

#add_executable(testcpp testcpp.cpp quickjspp.h quickjspp.cpp)
#target_link_libraries(testcpp quickjs)

SET(quickjs_src cutils.c cutils.h
        libbf.c libbf.h
        libregexp.c libregexp.h
        libunicode.c libunicode.h libunicode-table.h
        quickjs.c quickjs.h quickjs-atom.h
		quickjs-libc.c quickjs-libc.h quickjs-opcode.h)

add_library(quickjs STATIC ${quickjs_src} ${WIN_HLP_F})
target_compile_options(quickjs PRIVATE ${qjs_cflags})

add_library(quickjspp STATIC quickjspp.h quickjspp.cpp)
target_compile_options(quickjspp PRIVATE ${qjs_cflags})
target_link_libraries(quickjspp quickjs)


#add_library(quickjs-dumpleaks ${quickjs_src} ${WIN_HLP_F})
#target_compile_definitions(quickjs-dumpleaks PRIVATE DUMP_LEAKS=1)
#target_compile_options(quickjs-dumpleaks PRIVATE ${qjs_cflags})

#if (CMAKE_BUILD_TYPE MATCHES Debug)
#    target_compile_definitions(quickjs PRIVATE DUMP_LEAKS)
#endif()


#if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
#    target_link_libraries(libqjs atomic)
#endif()

#enable_testing()
#add_subdirectory(test)
