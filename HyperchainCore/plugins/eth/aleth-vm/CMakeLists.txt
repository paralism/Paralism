#
# HC:
#
FILE(GLOB tools_SRC  "${PROJECT_SOURCE_DIR}/../../newLog.cpp")
add_executable(aleth-vm main.cpp ${tools_SRC})

target_link_libraries(aleth-vm PRIVATE cppzmq libzmq cppzmq-static libzmq-static)
target_link_libraries(aleth-vm PRIVATE Boost::iostreams Boost::fiber)

target_link_libraries(aleth-vm PRIVATE hyperchainspace ethereum evm ethashseal devcore Boost::program_options)

target_include_directories(aleth-vm PRIVATE ../utils ${ETHASH_ROOT}/include ${PROJECT_SOURCE_DIR}/../../thirdparty)

install(TARGETS aleth-vm EXPORT alethTargets DESTINATION bin)
