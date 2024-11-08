#Copyright 2016-2022 hyperchain.net (Hyperchain)
#Distributed under the MIT software license, see the accompanying
#file COPYING or https://opensource.org/licenses/MIT.

#Permission is hereby granted, free of charge, to any person obtaining a copy of this
#software and associated documentation files (the "Software"), to deal in the Software
#without restriction, including without limitation the rights to use, copy, modify, merge,
#publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
#to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies or
#substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
#INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
#PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE

#FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#DEALINGS IN THE SOFTWARE.
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.7)

set(CMAKE_CXX_STANDARD 17)

if(UNIX)

add_definitions(-D_DEBUG)
add_definitions(-DDEBUG)

SET(HC_FLAG "$ENV{CXXFLAGS} -Wall -rdynamic -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "${HC_FLAG} -ggdb -O0 -g")
SET(CMAKE_CXX_FLAGS_RELEASE "${HC_FLAG} -O3")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /ZI /Od /MDd")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /utf-8")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX /DUDT_EXPORTS -DWIN32)

endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

ADD_DEFINITIONS(-D_HAS_STD_BYTE=0)


PROJECT(hc)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
if(NOT WIN32)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release)
ENDIF()
message(STATUS "Build Type: " "${CMAKE_BUILD_TYPE}")



#include current directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(SQLite3 REQUIRED)
if(SQLite3_FOUND)
    message(STATUS "Found SQLite3")
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found openssl")
endif()

find_package(cpprestsdk REQUIRED)
if(cpprestsdk_FOUND)
    message(STATUS "Found cpprestsdk")
endif()

find_package(cppzmq CONFIG REQUIRED)
if(cppzmq_FOUND)
    message(STATUS "Found ZeroMQ")
endif()

#refer to: https://www.boost.org/doc/libs/1_73_0/doc/html/stacktrace/configuration_and_build.html
ADD_DEFINITIONS(-DBOOST_STACKTRACE_LINK)
if(UNIX)
	set(STACKTRACE stacktrace_addr2line)
elseif(WIN32)
	set(STACKTRACE stacktrace_windbg)
endif()

#set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization fiber iostreams log ${STACKTRACE})

if(UNIX)
    find_package(breakpad REQUIRED)
elseif(WIN32)
    find_package(unofficial-breakpad CONFIG REQUIRED)
endif()





cmake_policy(SET CMP0071 NEW)

if( NOT DEFINED PACK_HYPERCHAIN )
	set(EXE_ICON "logo.ico")
else()
	set(EXE_ICON "logo-hc.ico")
endif()

#set(CMAKE_AUTOMOC TRUE)
#set(CMAKE_AUTORCC TRUE)
include( VERSION.cmake )
configure_file (
"${PROJECT_SOURCE_DIR}/logo.rc.in"
"${PROJECT_BINARY_DIR}/logo.rc")

include( UPDATEURL.cmake )
message(STATUS "*********************************************************************************")
message(STATUS "* Using updating URL: " ${MIRALL_UPDATE_STRING})
message(STATUS "*********************************************************************************")

configure_file (
"${PROJECT_SOURCE_DIR}/globalconfig.h.in"
"${PROJECT_BINARY_DIR}/globalconfig.h")

set(main_SRC main.cpp newLog.cpp)
set(main_HEAD newLog.h ${PROJECT_BINARY_DIR}/globalconfig.h) 

FILE(GLOB linenoise_SRC "thirdparty/linenoise-ng/*.cpp")
FILE(GLOB linenoise_HEAD "thirdparty/linenoise-ng/*.h")
#All source files
#
#
# 特别提示，非常重要！！！
# hyperchainspace.lib 已经包含了依赖代码，所以hc工程不能再次重复引入。
# 原因是Linux下的实测发现，如果重复包含，全局对象会创建二个实例，如UDT实例，引发程序运行异常
#
#
set(final_HEAD ${main_HEAD})
set(final_SRC ${main_SRC})

if(WIN32)
	set(resource_SRC ${CMAKE_BINARY_DIR}/logo.rc)
endif()

if(WIN32)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /level='requireAdministrator' /uiAccess='false' /SUBSYSTEM:CONSOLE" )
endif()

#install componet definition
set(CORECOMPONET "HyperChain")

add_subdirectory(vm)
add_subdirectory(HyperChain)
add_subdirectory(plugins)
add_subdirectory(Autoupdate)
add_subdirectory(genmd5)

# build liblinenoise
add_library(linenoise STATIC ${linenoise_SRC} ${linenoise_HEAD})
if(NOT WIN32)
target_compile_options(linenoise PRIVATE -fPIC)
endif()

add_executable(${PROJECT_NAME} ${resource_SRC} ${final_SRC} ${final_HEAD} ${WRAP_FILES})

if(WIN32)
	target_link_libraries(${PROJECT_NAME} bcrypt.lib)
else()
	target_link_libraries(${PROJECT_NAME} dl ssl)
	set_target_properties(${PROJECT_NAME} PROPERTIES BUILD_RPATH "$ORIGIN;$ORIGIN/lib")
	set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_RPATH "$ORIGIN;$ORIGIN/lib")
endif()


target_link_libraries(${PROJECT_NAME} cpprestsdk::cpprest OpenSSL::Crypto ${SQLITE3_LIBRARIES})
target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::iostreams Boost::filesystem Boost::thread Boost::fiber)
target_link_libraries(${PROJECT_NAME} unofficial::breakpad::libbreakpad_client)
target_link_libraries(${PROJECT_NAME} hyperchainspace Boost::${STACKTRACE})

target_include_directories(${PROJECT_NAME} PRIVATE
	${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/thirdparty ${breakpad_INCLUDE_DIRS})

include(HyperChainCPack.cmake)




