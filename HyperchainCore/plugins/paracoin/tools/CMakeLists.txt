#Copyright 2016-2021 hyperchain.net (Hyperchain)
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

SET(HC_FLAG "$ENV{CXXFLAGS} -Wall -ggdb -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "${HC_FLAG} -O0 -g")
SET(CMAKE_CXX_FLAGS_RELEASE "${HC_FLAG} -O3")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /MDd")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX /DUDT_EXPORTS)

endif()

#set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

PROJECT(stat)

IF( NOT CMAKE_BUILD_TYPE )
   SET(CMAKE_BUILD_TYPE Release)
ENDIF()
message(STATUS "Build Type: " "${CMAKE_BUILD_TYPE}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../chfast-ethash/include)

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
#find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization)


FILE(GLOB tools_SRC  "../../../newLog.cpp")
FILE(GLOB tools_HEAD "*.h" )


#All source files
set(final_HEAD
	${common_HEAD}
	${tools_HEAD}
	${paracoin_HEAD}
	)

set(final_SRC
	${common_SRC}
	${tools_SRC}
	${paracoin_SRC}
	${node_SRC}
	${udt_SRC}
	${db_SRC}
	)


add_executable(${PROJECT_NAME} "stat.cpp" ${final_SRC} ${final_HEAD} ${WRAP_FILES})
target_link_libraries(${PROJECT_NAME} Oracle::BerkeleyDB OpenSSL::Crypto hyperchainspace)
target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::iostreams Boost::filesystem Boost::thread Boost::fiber Boost::chrono)
target_link_libraries(${PROJECT_NAME} ethash)

SET(MIGR migr)
add_executable(${MIGR} "migr.cpp" ${final_SRC} ${final_HEAD} ${WRAP_FILES})
target_link_libraries(${MIGR} Oracle::BerkeleyDB OpenSSL::Crypto hyperchainspace)
target_link_libraries(${MIGR} Boost::system Boost::program_options Boost::serialization Boost::iostreams Boost::filesystem Boost::thread Boost::fiber Boost::chrono)
target_link_libraries(${MIGR} ethash)

SET(WALLET_MGR walletmgr)
add_executable(${WALLET_MGR} "walletmgr.cpp" ${final_SRC} ${final_HEAD} ${WRAP_FILES})
target_link_libraries(${WALLET_MGR} Oracle::BerkeleyDB OpenSSL::Crypto hyperchainspace)
target_link_libraries(${WALLET_MGR} Boost::system Boost::program_options Boost::serialization Boost::iostreams Boost::filesystem Boost::thread Boost::fiber Boost::chrono)
target_link_libraries(${WALLET_MGR} ethash)

if(UNIX)
target_link_libraries(${PROJECT_NAME} dl ssl)
target_link_libraries(${MIGR} dl ssl)
target_link_libraries(${WALLET_MGR} dl ssl)
endif()

configure_file (
"${PROJECT_SOURCE_DIR}/../../../globalconfig.h.in"
"${PROJECT_BINARY_DIR}/globalconfig.h")

install(TARGETS ${WALLET_MGR} DESTINATION bin COMPONENT ${CORECOMPONET})