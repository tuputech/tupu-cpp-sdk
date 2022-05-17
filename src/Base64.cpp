/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2022, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
// #include <stdexcept>
// #include <cctype>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "Base64.hpp"

using namespace std;

string TUPU::base64_encode(const void * input, size_t input_len)
{
    BIO *bmem, *b64;
    BUF_MEM * bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    //Ignore newlines - write everything in one line
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, input, input_len);
    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        return "";
    }
    BIO_get_mem_ptr(b64, &bptr);

    char * buffer = (char *)malloc(bptr->length + 1);
    memcpy(buffer, bptr->data, bptr->length);
    buffer[bptr->length] = 0;
    string result(buffer, bptr->length + 1);
    free(buffer);

    //BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    return result;
}

//Calculates the length of a decoded string
size_t calcDecodeLength(const char* b64input)
{
    size_t len = strlen(b64input),
        padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

int TUPU::base64_decode(const string & ascdata, void **buf_ptr, size_t *but_len)
{
    BIO *bmem, *b64;

    size_t input_len = ascdata.size() + 1;
    char *input = (char *)malloc(input_len);
    memset(input, 0, input_len);
    strcpy(input, ascdata.c_str());

    int length = calcDecodeLength(input);
    unsigned char *buffer = (unsigned char*)malloc(length + 1);
    memset(buffer, 0, length + 1);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, -1);
    b64 = BIO_push(b64, bmem);

    //Do not use newlines to flush buffer
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    size_t len = BIO_read(b64, buffer, length);
    assert(len == (size_t)length);
    //string result((char*)buffer, length);

    //free(buffer);
    BIO_free_all(b64);

    *buf_ptr = buffer;
    *but_len = length;

    free(input);

    return 0;
}
