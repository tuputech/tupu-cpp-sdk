###############################################################################
# TUPU Recognition API SDK
# Copyright(c)2013-2016, TUPU Technology
# http://www.tuputech.com
###############################################################################



cmake_minimum_required (VERSION 2.8)

project (Demo1)

if (debug)
    set(CMAKE_VERBOSE_MAKEFILE ON)
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -O0")
    message(STATUS ${CMAKE_SYSTEM_NAME})
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(CMAKE_MACOSX_RPATH 1)
endif ()
set(CMAKE_CXX_FLAGS "-O2 -g -Wall -Wno-unused-function -std=c++11")

#set(OPENSSL_ROOT_PATH "/usr/local/Cellar/openssl/1.0.2o_2")
#set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_PATH}/include")

find_package(OpenSSL)
find_package(CURL)

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/include
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src)
add_subdirectory(test)
