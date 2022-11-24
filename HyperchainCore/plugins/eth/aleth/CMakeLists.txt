set(
    sources
    AccountManager.cpp AccountManager.h
    alethmain.cpp
    alethapi.cpp alethapi.h
    cryptoethcurrency.cpp cryptoethcurrency.h
    MinerAux.cpp MinerAux.h
    blocktriaddr.h
    hyperblockmsgs.h hyperblockmsgs.cpp
)

#add_executable(aleth ${sources})
add_library(aleth SHARED ${sources})
set_target_properties(aleth PROPERTIES DEBUG_POSTFIX "")

target_link_libraries(
    aleth
    PRIVATE hyperchainspace ethereum ethashseal evm web3jsonrpc webthree devcore Boost::program_options
    Snappy::snappy
)

target_link_libraries(aleth PRIVATE cppzmq libzmq cppzmq-static libzmq-static)
target_link_libraries(aleth PRIVATE Boost::iostreams Boost::fiber)

target_include_directories(aleth PRIVATE ../utils
		${CMAKE_SOURCE_DIR}
                ${PROJECT_SOURCE_DIR}/../common
		${CMAKE_SOURCE_DIR}/thirdparty ${ETHASH_ROOT}/include)


if(MINIUPNPC)
    target_compile_definitions(aleth PRIVATE ETH_MINIUPNPC)
endif()

install(TARGETS aleth DESTINATION bin)
