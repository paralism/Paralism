add_executable(rlp main.cpp)
target_include_directories(rlp PRIVATE "${UTILS_INCLUDE_DIR}" ${ETHASH_ROOT}/include)
target_link_libraries(rlp PRIVATE devcrypto devcore Boost::program_options)

if(NOT WIN32)
    target_link_libraries(rlp PRIVATE rt dl) 
endif()

