
set(sources
    getaccountpwd.cpp 
)

add_executable(getaccountpwd ${sources})

target_link_libraries(getaccountpwd PRIVATE Boost::system Boost::date_time)
if(NOT WIN32)
    target_link_libraries(getaccountpwd PRIVATE rt pthread) 
endif()

install(TARGETS getaccountpwd DESTINATION bin COMPONENT ${CORECOMPONET})


