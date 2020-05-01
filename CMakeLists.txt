cmake_minimum_required (VERSION 2.8)

set(lib_name fw_dns_plug)
project(fw_dns_plug)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

include_directories(${PROJECT_SOURCE_DIR}/inc/)
include_directories(/opt/MESA/include/)

option(ENABLE_WARNING_ALL "Enable all optional warnings which are desirable for normal code" TRUE)
option(ENABLE_SANITIZE_ADDRESS "Enable AddressSanitizer" FALSE)
option(ENABLE_SANITIZE_THREAD "Enable ThreadSanitizer" FALSE)

if(ENABLE_SANITIZE_ADDRESS)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ENABLE_SANITIZE_THREAD)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()

set(CMAKE_INSTALL_PREFIX /home/mesasoft/sapp_run)

add_subdirectory (src) 

set(CONFLIST /plug/conflist.inf)
set(MASTER_INF "./plug/business/fw_dns_plug/fw_dns_plug.inf")
set(MAIN_CONF /tsgconf/main.conf)

file(WRITE ${PROJECT_SOURCE_DIR}/install.sh "#!/bin/sh\r\n")
file(WRITE ${PROJECT_SOURCE_DIR}/uninstall.sh "#!/bin/sh\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "DST=\${RPM_INSTALL_PREFIX}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "DST=\${RPM_INSTALL_PREFIX}\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "mkdir -p \${DST}/plug/business/\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "mkdir -p \${DST}/plug/business/\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "touch \${DST}${CONFLIST}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "touch \${DST}${CONFLIST}\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "mkdir -p \${DST}/tsgconf/\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "mkdir -p \${DST}/tsgconf/\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "touch \${DST}${MAIN_CONF}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "touch \${DST}${MAIN_CONF}\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "if [[ -z `grep -rn 'fw_dns_plug.inf' \${DST}${CONFLIST}` ]];then\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "\tsed -i '/\\[business\\]/a\\${MASTER_INF}' \${DST}${CONFLIST}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "fi\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "sed -i '/fw_dns_plug.inf/d' \${DST}${CONFLIST}\r\n")

file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "if [[ -z `grep -rn '\\[DNS_PLUG\\]' \${DST}${MAIN_CONF}` ]];then\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "\tsed -i '1i\\\\[DNS_PLUG\\]' \${DST}${MAIN_CONF}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "\tsed -i '/\\[DNS_PLUG\\]/a\\LOG_LEVEL=30' \${DST}${MAIN_CONF}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "\tsed -i '/\\[DNS_PLUG\\]/a\\LOG_PATH=./tsglog/fw_dns_plug/fw_dns_plug' \${DST}${MAIN_CONF}\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/install.sh "fi\r\n")
file(APPEND ${PROJECT_SOURCE_DIR}/uninstall.sh "sed -i '/\\[DNS_PLUG\\]/,+2d' \${DST}${MAIN_CONF}\r\n")

SET(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/install.sh")
SET(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${PROJECT_SOURCE_DIR}/uninstall.sh")

include(Package)
