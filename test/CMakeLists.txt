###############################################################################
# TUPU Recognition API SDK
# Copyright(c)2013-2016, TUPU Technology
# http://www.tuputech.com
###############################################################################



include_directories(
    ${PROJECT_SOURCE_DIR}/src
)

add_executable(test test.cpp)
target_link_libraries(test tupu_static ${OPENSSL_LIBRARIES} ${CURL_LIBRARY})

#add_executable(testsign test-sign.cpp)
#target_link_libraries(testsign ${OPENSSL_LIBRARIES})
