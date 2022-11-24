file(GLOB sources "*.cpp" "*.h")

add_library(ethereum ${sources})

target_include_directories(ethereum PRIVATE ${CMAKE_SOURCE_DIR} ${UTILS_INCLUDE_DIR})
target_link_libraries(ethereum PUBLIC evm ethcore p2p devcrypto devcore PRIVATE jsoncpp_lib_static Snappy::snappy Boost::fiber Boost::context)
#target_link_libraries(ethereum debug evm ethcore p2p devcrypto devcore jsoncpp_lib_static Snappy::snappy Boost::fiber Boost::context)
