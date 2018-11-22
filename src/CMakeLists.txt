###############################################################################
# TUPU Recognition API SDK
# Copyright(c)2013-2016, TUPU Technology
# http://www.tuputech.com
###############################################################################


set(LIB_SRCS Base64.cpp TImage.cpp Recognition.cpp jsmn.c) 

#link_directories(${OPENSSL_LIBRARIES} ${CURL_LIBRARY})
add_library(tupu SHARED ${LIB_SRCS} ${OPENSSL_LIBRARIES} ${CURL_LIBRARY})

add_library(tupu_static STATIC ${LIB_SRCS})
set_target_properties(tupu_static PROPERTIES OUTPUT_NAME tupu)
