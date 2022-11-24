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

SET(HC_FLAG "$ENV{CXXFLAGS} -Wall -fstack-protector -fstack-protector-all")
SET(CMAKE_CXX_FLAGS_DEBUG "${HC_FLAG} -ggdb -O0 -g")
SET(CMAKE_CXX_FLAGS_RELEASE "${HC_FLAG} -O3")

elseif(WIN32)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MD")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Zi /Od /MDd")

ADD_DEFINITIONS(/D__WXMSW__ /DNOMINMAX /DUDT_EXPORTS)

endif()

#remove the define of PROJECT_NAME
PROJECT(Autoupdate)
set(PROJECT_NAME)

PROJECT(genmd5)

IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release)
ENDIF()

find_package(cpprestsdk REQUIRED)
if(cpprestsdk_FOUND)
    message(STATUS "Found cpprestsdk")
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found openssl")
endif()

find_package (Boost REQUIRED COMPONENTS filesystem)

set(main_SRC genmd5.cpp ../UpdateInfo.cpp ../util/md5.cpp ../globalconfig.cpp)
set(main_HEAD ../UpdateInfo.h ../util/md5.h)

add_executable(${PROJECT_NAME} ${main_SRC} ${main_HEAD} )

if(WIN32)
target_link_libraries(${PROJECT_NAME} bcrypt.lib)
else()
target_link_libraries(${PROJECT_NAME} dl ssl)
endif()

target_link_libraries(${PROJECT_NAME} cpprestsdk::cpprest OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} Boost::filesystem)
target_include_directories(${PROJECT_NAME} PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/..
	${CMAKE_CURRENT_SOURCE_DIR}/../util
	${CMAKE_BINARY_DIR})

