add_library(webthree WebThree.cpp WebThree.h)
target_include_directories(webthree PRIVATE ../utils ${ETHASH_ROOT}/include)
target_link_libraries(webthree PUBLIC ethereum p2p devcore)
