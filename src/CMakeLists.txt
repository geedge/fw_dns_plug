cmake_minimum_required(VERSION 2.8)

add_definitions(-fPIC)

set(SRC fw_dns_plug.cpp fw_dns_rule.cpp) 

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(/opt/MESA/include/)
include_directories(/opt/MESA/include/tsg/)

set(FW_DNS_PLUG_DEPEND_DYN_LIB  MESA_handle_logger MESA_prof_load maatframe pthread MESA_field_stat2)

add_library(fw_dns_plug SHARED ${SRC})
target_link_libraries(fw_dns_plug ${FW_DNS_PLUG_DEPEND_DYN_LIB})
set_target_properties(fw_dns_plug  PROPERTIES PREFIX "")

install(TARGETS fw_dns_plug LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/business/fw_dns_plug COMPONENT LIBRARY)
install(FILES ../bin/fw_dns_plug.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/business/fw_dns_plug COMPONENT PROFILE)

