add_executable(test_consensus
    test_consensus_engine.cpp
    test_crosschaintx.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_consensus PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_consensus gtest Boost::serialization Boost::system pthread)
gtest_discover_tests(test_consensus)
