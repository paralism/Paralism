file(GLOB sources "*.cpp" "*.h")


add_library(ethcore ${sources})

#HC: add ${ETHASH_ROOT}/include for include directories
target_include_directories(ethcore PRIVATE "${UTILS_INCLUDE_DIR}" "${ETHASH_ROOT}/include")
target_include_directories(ethcore PRIVATE ${CMAKE_SOURCE_DIR})

target_link_libraries(ethcore PUBLIC hyperchainspace ethereum devcrypto devcore)
