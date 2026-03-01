add_executable(test_util
    test_mutexobj.cpp
    test_common.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_util PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_util gtest pthread)
gtest_discover_tests(test_util)
