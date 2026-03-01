add_executable(test_hyperchain
    test_hyperchainspace.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_hyperchain PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_hyperchain gtest Boost::serialization Boost::system pthread)
gtest_discover_tests(test_hyperchain)
