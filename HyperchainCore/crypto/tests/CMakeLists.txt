add_executable(test_crypto
    test_digest.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_crypto PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_crypto gtest pthread)
gtest_discover_tests(test_crypto)
