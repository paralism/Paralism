
add_definitions(-DALETH)

FILE(GLOB common_SRC "../../common/utilc.cpp")
FILE(GLOB common_HEAD "../../common/utilc.h")

set(
    sources
    AccountManager.cpp AccountManager.h
    alethmain.cpp
    alethapi.cpp alethapi.h
    alethaux.cpp
    cryptoethcurrency.cpp cryptoethcurrency.h
    MinerAux.cpp MinerAux.h
    blocktriaddr.h
    hyperblockmsgs.h hyperblockmsgs.cpp
)

#add_executable(aleth ${sources})
add_library(aleth SHARED ${sources} ${common_SRC})
set_target_properties(aleth PROPERTIES DEBUG_POSTFIX "")


if(NOT WIN32) 
    target_compile_options(aleth PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../export.lds)
    target_compile_options(aleth PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../export-eth.lds)
endif()



target_link_libraries(
    aleth
    PRIVATE hyperchainspace ethereum ethashseal evm web3jsonrpc webthree devcore Boost::program_options
    Snappy::snappy
)

target_link_libraries(aleth PRIVATE cppzmq libzmq cppzmq-static libzmq-static)
target_link_libraries(aleth PRIVATE Boost::iostreams Boost::fiber Boost::${STACKTRACE})


target_include_directories(aleth PRIVATE ../utils
    ${CMAKE_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/../common
    ${CMAKE_SOURCE_DIR}/thirdparty ${ETHASH_ROOT}/include)


if(MINIUPNPC)
    target_compile_definitions(aleth PRIVATE ETH_MINIUPNPC)
endif()

install(TARGETS aleth DESTINATION bin COMPONENT ${CORECOMPONET})
