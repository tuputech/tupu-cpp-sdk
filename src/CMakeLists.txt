###############################################################################
# TUPU Recognition API SDK
# Copyright(c)2013-2016, TUPU Technology
# http://www.tuputech.com
###############################################################################


set(LIB_SRCS Base64.cpp TImage.cpp Recognition.cpp jsmn.c) 

add_library(tupu SHARED ${LIB_SRCS}) 

add_library(tupu_static STATIC ${LIB_SRCS})
set_target_properties(tupu_static PROPERTIES OUTPUT_NAME tupu)
