add_executable(test_db
    test_dbmgr.cpp
    test_restapi.cpp
    ${CMAKE_SOURCE_DIR}/tests/test_main.cpp
)
target_include_directories(test_db PRIVATE ${CMAKE_SOURCE_DIR}/tests/common)
target_link_libraries(test_db gtest Boost::serialization Boost::system sqlite3 pthread)
gtest_discover_tests(test_db)
