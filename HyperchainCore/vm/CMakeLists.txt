cmake_minimum_required(VERSION 3.7)
set(CMAKE_CXX_STANDARD 17)

PROJECT(vm)

add_subdirectory(quickjs)

find_package (Boost REQUIRED COMPONENTS system program_options date_time filesystem thread serialization)


FILE(GLOB SRC "*.cpp")
FILE(GLOB HEAD "*.h")


add_library(${PROJECT_NAME} STATIC ${SRC} ${HEAD})

if(UNIX)
target_compile_options(${PROJECT_NAME} PRIVATE -fPIC)
endif()

target_link_libraries(${PROJECT_NAME} quickjspp)


target_link_libraries(${PROJECT_NAME} Boost::system Boost::program_options Boost::serialization Boost::filesystem Boost::thread)

