add_executable(test_node
    test_uint128.cpp
    test_singleton.cpp
    test_mqmsg.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_node PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_node gtest Boost::serialization Boost::system pthread)
gtest_discover_tests(test_node)
