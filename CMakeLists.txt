cmake_minimum_required(VERSION 3.22)
project(cjks C)

# Includes
include(GNUInstallDirs)
include(CTest)
include(CheckIncludeFile)
include(CheckSourceCompiles)

# OSX
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Valgrind memcheck
find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --show-leak-kinds=all")

# bits
CHECK_INCLUDE_FILE("endian.h" HAS_ENDIAN_H)

# Compilation options
file(GLOB CJKS_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB CJKS_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/cjks/*.h)

if (${CJKS_STATIC})
    add_library(cjks STATIC ${CJKS_SOURCE})
else()
    add_library(cjks SHARED ${CJKS_SOURCE})
endif()

if (${HAS_ENDIAN_H})
    target_compile_definitions(cjks PUBLIC HAS_ENDIAN_H)
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

# Linkage
find_package(Iconv REQUIRED)
find_package(OpenSSL REQUIRED)

# Check iconv
set(CJKS_INCLUDES ${Iconv_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set(CMAKE_REQUIRED_INCLUDES "${CJKS_INCLUDES}")
set(CMAKE_REQUIRED_LIBRARIES "${Iconv_LIBRARIES}")

set(ICONV_TEST_CODE "
#include <stdlib.h>
#include <iconv.h>
int main() {
iconv_open(NULL, NULL);
return 0;
}
")

check_source_compiles(C "${ICONV_TEST_CODE}" ICONV_COMPILES)

if (NOT ICONV_COMPILES)
    set(CMAKE_REQUIRED_DEFINITIONS -DLIBICONV_PLUG)
    check_source_compiles(C "${ICONV_TEST_CODE}" LIBICONV_COMPILES)
endif()

if (LIBICONV_COMPILES)
    target_compile_definitions(cjks PRIVATE LIBICONV_PLUG)
endif()

set(CJKS_LINKS Iconv::Iconv OpenSSL::Crypto)
if (MSVC)
    set(CJKS_LINKS ${CJKS_LINKS} OpenSSL::applink ws2_32)
endif()

target_link_libraries(cjks 
    PRIVATE
        ${CJKS_LINKS}
)

target_include_directories(cjks 
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

set_target_properties(cjks
    PROPERTIES
    PUBLIC_HEADER "${CJKS_HEADERS}"
)

# TESTS
if (${CJKS_TEST})
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
endif()

add_executable(cjkstool ${CMAKE_CURRENT_SOURCE_DIR}/cli/cjks.c)
set_target_properties(cjkstool PROPERTIES OUTPUT_NAME cjks)
target_link_libraries(cjkstool ${CJKS_LINKS} cjks)

# INSTALL Section
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/library_config/libcjks.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libcjks.pc" @ONLY)

install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/libcjks.pc"
    DESTINATION lib/pkgconfig
)

install(
    TARGETS cjks cjkstool
    EXPORT cjks_targets
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cjks
)

install(EXPORT cjks_targets FILE cjksConfig.cmake DESTINATION lib/cmake/cjks)

if (NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/library_config/uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/library_config/uninstall.cmake"
        @ONLY
    )
    add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/library_config/uninstall.cmake")
endif()