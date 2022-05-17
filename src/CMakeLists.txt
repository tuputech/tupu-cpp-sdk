###############################################################################
# TUPU Recognition API SDK
# Copyright(c)2013-2022, TUPU Technology
# http://www.tuputech.com
###############################################################################


set(LIB_SRCS Base64.cpp TImage.cpp Recognition.cpp jsmn.c) 

#message(STATUS "check before build library: ${OPENSSL_CRYPTO_LIBRARY}")
#target_link_libraries(tupu ${OPENSSL_CRYPTO_LIBRARY} ${CURL_LIBRARIES})

add_library(tupu SHARED ${LIB_SRCS})
set_target_properties(tupu PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
target_link_libraries(tupu OpenSSL::Crypto CURL::libcurl)

add_library(tupu_static STATIC ${LIB_SRCS})
set_target_properties(tupu_static PROPERTIES OUTPUT_NAME tupu)
