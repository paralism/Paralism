set(
    sources
    main.cpp
)

add_executable(aleth-bootnode ${sources})
target_link_libraries(
    aleth-bootnode
    PRIVATE 
    p2p hyperchainspace devcore Boost::program_options
    Boost::iostreams Boost::fiber
)

if(NOT WIN32)
    target_link_libraries(aleth-bootnode PRIVATE dl) 
endif()

target_include_directories(aleth-bootnode PRIVATE ${CMAKE_SOURCE_DIR} "${ETHASH_ROOT}/include")

install(TARGETS aleth-bootnode DESTINATION bin)
