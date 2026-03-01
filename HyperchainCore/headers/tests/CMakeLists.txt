add_executable(test_headers
    test_sha256.cpp
    test_commonstruct.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_headers PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_headers gtest Boost::serialization Boost::system pthread)
gtest_discover_tests(test_headers)
