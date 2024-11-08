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

SET(HC_FLAG "$ENV{CXXFLAGS} -Wall -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${HC_FLAG} -ggdb -O0 -g")
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${HC_FLAG} -O3")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /ZI /Od /MDd")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX /DUDT_EXPORTS)

endif()

#set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

#remove the define of PROJECT_NAME
PROJECT(paracoin)
set(PROJECT_NAME)
add_subdirectory(chfast-ethash ethash)

PROJECT(paracoin)

IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release)
ENDIF()
message(STATUS "Build Type: " "${CMAKE_BUILD_TYPE}")


#include current directory
set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found openssl")
endif()

if (NOT TARGET Oracle::BerkeleyDB)
	find_package(BerkeleyDB REQUIRED)
endif()

#set(Boost_USE_STATIC_LIBS ON)
find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization iostreams)

set(HYPERCHAIN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

FILE(GLOB common_SRC "../common/*.cpp" "../common/cryptopp/*.cpp")
FILE(GLOB common_HEAD "../common/*.h" "../common/json/*.h" "../common/cryptopp/*.h")


FILE(GLOB paracoin_sp_SRC "../common/support/*.cpp" "../common/util/*.cpp")
FILE(GLOB paracoin_sp_HEAD "../common/support/*.h" "../common/util/*.h")

FILE(GLOB paracoin_pp_SRC  "../common/crypto/*.cpp" "../common/crypto/ctaes/*.c" )
FILE(GLOB paracoin_pp_HEAD "../common/crypto/*.hpp" "../common/crypto/ctaes/*.h" "../common/crypto/equihash.tcc" )

FILE(GLOB paracoin_SRC "*.cpp")
FILE(GLOB paracoin_HEAD "*.h")

set(paracoin_SRC ${paracoin_SRC} ${paracoin_pp_SRC} ${paracoin_sp_SRC})
set(paracoin_HEAD ${paracoin_HEAD} ${paracoin_pp_HEAD} ${paracoin_sp_HEAD})


#All source files
set(final_HEAD
	${common_HEAD}
	${paracon_HEAD}
	${HyperChain_HEAD}
	)

set(final_SRC
	${common_SRC}
	${paracoin_SRC}
	)


add_library(${PROJECT_NAME} SHARED ${final_SRC} ${final_HEAD})

if(NOT WIN32) 
    target_compile_options(${PROJECT_NAME} PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../export.lds)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../export-paracoin.lds)
endif()



#set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX "")
set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX "")

target_link_libraries(${PROJECT_NAME} Oracle::BerkeleyDB OpenSSL::Crypto hyperchainspace)
target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::iostreams Boost::filesystem Boost::thread Boost::fiber)
target_link_libraries(${PROJECT_NAME} ethash)
target_link_libraries(${PROJECT_NAME} cppzmq libzmq cppzmq-static libzmq-static)
target_link_libraries(${PROJECT_NAME} quickjs secp256k1-lp)
target_include_directories(${PROJECT_NAME} PRIVATE
						${CMAKE_SOURCE_DIR}
						${CMAKE_SOURCE_DIR}/thirdparty
						${PROJECT_SOURCE_DIR}/../common
						${PROJECT_SOURCE_DIR}/../common/secp256k1/include
						)


configure_file (
"${PROJECT_SOURCE_DIR}/../../globalconfig.h.in"
"${PROJECT_BINARY_DIR}/globalconfig.h")

add_subdirectory(tools)

install(TARGETS ${PROJECT_NAME} DESTINATION bin COMPONENT ${CORECOMPONET})
