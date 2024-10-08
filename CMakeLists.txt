cmake_minimum_required(VERSION 3.22)
project(cjks C)

include(GNUInstallDirs)
include(CTest)
find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --show-leak-kinds=all")

find_program(KEYTOOL_COMMAND keytool)

file(GLOB CJKS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB CJKS_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/cjks/*.h)

if (${CJKS_STATIC})
    add_library(cjks STATIC ${CJKS_SOURCE})
else()
    add_library(cjks SHARED ${CJKS_SOURCE})
endif()

if (${CJKS_STATIC})
    target_compile_definitions(cjks PRIVATE CJKS_STATIC)
else()
    target_compile_definitions(cjks PRIVATE CJKS_DLL_EXPORT)
endif()

if (MSVC)
    target_compile_options(cjks PRIVATE /W4)
else()
    target_compile_options(cjks PRIVATE -Wall -Wextra -pedantic)
endif()

find_package(Iconv REQUIRED)
find_package(OpenSSL REQUIRED)

set(CJKS_LINKS Iconv::Iconv OpenSSL::Crypto)
if (MSVC)
    set(CJKS_LINKS ${CJKS_LINKS} OpenSSL::applink ws2_32)
endif()

target_link_libraries(cjks 
    PRIVATE
        ${CJKS_LINKS}
)
target_include_directories(cjks PUBLIC
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

set_target_properties(cjks
    PROPERTIES
    PUBLIC_HEADER "${CJKS_HEADERS}"
)

set(CJKS_RES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/resources)

file(GLOB files tests/*.c)
foreach(file ${files})
    get_filename_component(tname ${file} NAME_WLE)
    add_executable(${tname} ${file})
    target_link_libraries(${tname} cjks ${CJKS_LINKS})
    if (${CJKS_STATIC})
        target_compile_definitions(${tname} PRIVATE CJKS_RES_DIR="${CJKS_RES_DIR}" CJKS_STATIC)
    else()
        target_compile_definitions(${tname} PRIVATE CJKS_RES_DIR="${CJKS_RES_DIR}")
    endif()
    add_test(NAME ${tname} COMMAND ${tname})
endforeach()

install(
    TARGETS cjks
    EXPORT cjks_targets
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cjks
)

install(EXPORT cjks_targets FILE cjksConfig.cmake DESTINATION lib/cjks)
