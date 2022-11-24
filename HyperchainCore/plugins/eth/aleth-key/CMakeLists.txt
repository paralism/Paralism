#
# HC:
#
FILE(GLOB tools_SRC "${PROJECT_SOURCE_DIR}/../../newLog.cpp")
add_executable(aleth-key KeyAux.h main.cpp ${tools_SRC})

target_link_libraries(aleth-key PRIVATE hyperchainspace ethereum ethcore devcore Boost::program_options)

target_link_libraries(aleth-key PRIVATE cppzmq libzmq cppzmq-static libzmq-static)
target_link_libraries(aleth-key PRIVATE Boost::iostreams Boost::fiber)


target_include_directories(aleth-key PRIVATE ${ETHASH_ROOT}/include ${PROJECT_SOURCE_DIR}/../../thirdparty)
install(TARGETS aleth-key EXPORT alethTargets DESTINATION bin)
