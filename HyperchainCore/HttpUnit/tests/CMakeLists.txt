add_executable(test_httpunit
    test_convert.cpp
    test_md5.cpp
    test_basesock.cpp
    test_switchsock.cpp
    test_httpunit.cpp
    test_mutex.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
    # 需要链接的源文件（独立编译的模块）
    ${CMAKE_SOURCE_DIR}/HttpUnit/md5.cpp
    ${CMAKE_SOURCE_DIR}/HttpUnit/sock.cpp
)
target_include_directories(test_httpunit PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/tests/common
)
target_link_libraries(test_httpunit gtest pthread)
gtest_discover_tests(test_httpunit)
