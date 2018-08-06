###############################################################################
# TUPU Recognition API SDK
# Copyright(c)2013-2016, TUPU Technology
# http://www.tuputech.com
###############################################################################



cmake_minimum_required (VERSION 2.8)

project (Demo1)
set(debug 0)    #default not print debug info, no debug symbol

if (debug)
    set(CMAKE_VERBOSE_MAKEFILE ON)
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -O0")
    message(STATUS ${CMAKE_SYSTEM_NAME})
endif ()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(CMAKE_MACOSX_RPATH 1)
endif ()
set(CMAKE_CXX_FLAGS "-O2 -g -Wall -Wno-unused-function -std=c++11")

set(OPENSSL_ROOT_PATH "/usr/local/Cellar/openssl/1.0.2o_2")  # default OPENSSL_ROOT_PATH, need change
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_PATH}/include")

find_package(OpenSSL)
find_package(CURL)

if (debug AND CURL_FOUND)
    message(STATUS "${CURL_INCLUDE_DIRS}")
    message(STATUS "${CURL_LIBRARIES}")
    message(STATUS "${CURL_VERSION_STRING}")
endif ()

if(${CURL_VERSION_STRING} STRLESS "7.56.0") # MIME API supported, curl_formadd is deprecated.
    message(FATAL_ERROR "curl version neeed at least 7.56.0")
endif()

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src)
add_subdirectory(test)
