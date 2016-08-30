/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <curl/curl.h>

#include "jsmn.h"
#include "Base64.hpp"
#include "Recognition.hpp"


#ifndef VERB_LEV
#define VERB_LEV 0
#endif

#define TUPU_API "http://api.open.tuputech.com/v3/recognition/"
#define USER_AGENT "tupu-client/1.0"


using namespace std;

namespace TUPU
{

typedef struct {
  char *memory;
  size_t size;
} MemChunk;


static RSA * read_private_key(const string & key_path);
static RSA * read_public_key(const string & pubkeyStr);
static RSA * read_tupu_pubkey();
static int sign_with_sha256(const string & message, RSA * p_rsa, string & result);
static int verify_with_sha256(const string & message, const string & signature, RSA * p_rsa);
static void random_str(size_t len, char *output);
static void parse_json_value(const char *src, size_t len, string & result);
static size_t write_memory(void *contents, size_t size, size_t nmemb, void *userp);
static void compose_form(struct curl_httppost ** post,
    const string & timestamp, const string & nonce, const string & signature,
    const vector<string> & images, const vector<string> & tags);
#if VERB_LEV >= 2
static int debug_trace(CURL *curl, curl_infotype type, char *data, size_t size, void *userptr);
#endif




Recognition::Recognition(const string & rsaPrivateKeyPath)
    : m_rsaPrivateKey(NULL)
    , m_tupuPublicKey(NULL)
    , m_apiUrl(TUPU_API)
    , m_ua(USER_AGENT)
{
    generalInit(rsaPrivateKeyPath);
}

Recognition::Recognition(const string & rsaPrivateKeyPath, const string & apiUrl)
    : m_rsaPrivateKey(NULL)
    , m_tupuPublicKey(NULL)
    , m_apiUrl(apiUrl)
    , m_ua(USER_AGENT)
{
    generalInit(rsaPrivateKeyPath);
}

Recognition::~Recognition()
{
    RSA_free(m_rsaPrivateKey);
    RSA_free(m_tupuPublicKey);

    curl_global_cleanup();
}

void Recognition::generalInit(const string & rsaPrivateKeyPath)
{
    m_rsaPrivateKey = read_private_key(rsaPrivateKeyPath);
    m_tupuPublicKey = read_tupu_pubkey();

    curl_global_init(CURL_GLOBAL_ALL);
}


void Recognition::setUserAgent(const std::string & ua)
{
    m_ua = ua;
}


OpCode Recognition::perform(const string & secretId, string & result, long *statusCode,
    const vector<string> & images, const vector<string> & tags)
{
    if (secretId.size() <=0 || images.size() <= 0)
        return OPC_WRONGPARAM;

    OpCode opc = OPC_OK;
    size_t len = 3, hexLen = len * 2 + 1;
    char nonce[hexLen];
    random_str(len, nonce);

    time_t ts = time(NULL);
    char tsBuf[30];
    sprintf(tsBuf, "%ld", ts);


    stringstream s;
    s << secretId << "," << tsBuf << "," << nonce;
    string msg = s.str(), signature;

    int rc = sign_with_sha256(msg, m_rsaPrivateKey, signature);
    if (1 != rc) {
        return OPC_SIGNFAILED;
    }

    struct curl_httppost *formpost = NULL;
    compose_form(&formpost, tsBuf, nonce, signature, images, tags);
    if (NULL == formpost)
        return OPC_OTHERS;
    
    opc = this->sendRequest(secretId, formpost, result, statusCode);
    curl_formfree(formpost);
    return opc;
}

OpCode Recognition::sendRequest(const string & secretId, struct curl_httppost *post,
    string & result, long *statusCode)
{
    struct curl_slist *headerlist = NULL;
    static const char buf[] = "Expect: 100-continue";

    CURL *curl = NULL;
    CURLcode res = CURLE_OK;
    OpCode opc = OPC_OK;

    MemChunk chunk;
    chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */ 
    chunk.size = 0; 

    headerlist = curl_slist_append(headerlist, buf);

    curl = curl_easy_init();

    string url = m_apiUrl + secretId;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // set form-data to post
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);

    /* send all data to this function  */ 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory);
    /* we pass our 'chunk' struct to the callback function */ 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, m_ua.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

#if VERB_LEV >= 1
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#if VERB_LEV >= 2
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_trace);
#endif
#endif

    res = curl_easy_perform(curl);
    long httpcode = 0;
    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &httpcode);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        opc = OPC_SENDFAILED;
    }
    else if (httpcode >= 200 && httpcode < 300) {
        opc = this->handleResponse(chunk.memory, chunk.size, result);
    }
    else {
        opc = OPC_REQFAILED;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all (headerlist);

    free(chunk.memory);

    *statusCode = httpcode;
    return opc;
}

OpCode Recognition::handleResponse(const char * resp, size_t resp_len, string & result)
{
    jsmn_parser parser;
    size_t tk_len = 10;
    jsmntok_t tokens[tk_len];

    jsmn_init(&parser);
    int r = jsmn_parse(&parser, resp, resp_len, tokens, tk_len);
    if (r < 0) {
        fprintf(stderr, "Failed to parse JSON in response: %d\n", r);
        return OPC_PARSEFAILED;
    }

    string signature, json;

    for (int i = 0; i < r; i++) {
        jsmntok_t tk = tokens[i];
        if (JSMN_STRING == tk.type) {
            string key(resp + tk.start, tk.end - tk.start);
            jsmntok_t tv = tokens[i+1];
            const char *vs = resp + tv.start;
            size_t vl = tv.end - tv.start;
            i++; //skip the value token

            if (0 == key.compare("json"))
                parse_json_value(vs, vl, json);
            else if (0 == key.compare("signature"))
                signature = string(vs, vl);
        }
    }

    int rc = verify_with_sha256(json, signature, m_tupuPublicKey);
    if (1 != rc) {
        return OPC_VERIFYFAILED;
    }
    result = json;

    return OPC_OK;
}








static
RSA * read_private_key(const string & key_path)
{
    RSA * p_rsa = NULL;
    FILE * file = NULL;

    if (NULL == (file = fopen(key_path.c_str(),"r")))
    {
        perror("open key file error");
        return NULL;
    }
 
    if (NULL == (p_rsa = PEM_read_RSAPrivateKey(file,NULL,NULL,NULL)))
    {
        ERR_print_errors_fp(stdout);
    }

    fclose(file);
        

    return p_rsa;
}

static
RSA * read_public_key(const string & pubkeyStr)
{
    BIO *bio = NULL;
    RSA *rsa = NULL;
    char *chPublicKey = const_cast<char *>(pubkeyStr.c_str());
    //read public key from string
    if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)
    {
        fprintf(stderr, "BIO_new_mem_buf failed!\n");
        return NULL;
    }
    //get rsa struct from bio
    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa)
    {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "Failed to load public key [%s]\n", errBuf);

        BIO_free_all(bio);
        return NULL;
    }

    BIO_free_all(bio);

    return rsa;
}

static
RSA * read_tupu_pubkey()
{
    string pubkeyStr = "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDyZneSY2eGnhKrArxaT6zswVH9\n"
        "/EKz+CLD+38kJigWj5UaRB6dDUK9BR6YIv0M9vVQZED2650tVhS3BeX04vEFhThn\n"
        "NrJguVPidufFpEh3AgdYDzOQxi06AN+CGzOXPaigTurBxZDIbdU+zmtr6a8bIBBj\n"
        "WQ4v2JR/BA6gVHV5TwIDAQAB\n"
        "-----END PUBLIC KEY-----\n";
    return read_public_key(pubkeyStr);
}

static
void to_sha256(const string & message, unsigned char *digest)
{
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, message.c_str(), message.size());
    SHA256_Final(digest, &c);
    OPENSSL_cleanse(&c, sizeof(c));
}

static
int sign_with_sha256(const string & message, RSA * p_rsa, string & result)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    to_sha256(message, digest);

    unsigned char * sig = NULL;
    unsigned int sig_len = 0;
    int rsa_len = RSA_size(p_rsa);
 
    sig = (unsigned char *)malloc(rsa_len);
    memset(sig, 0, rsa_len);
 
    int rc = RSA_sign(NID_sha256, digest, sizeof digest, sig, &sig_len, p_rsa);
    if (1 == rc)
    {
        result = base64_encode(sig, sig_len);
    }
    
    free(sig);

    return rc;
}

static
int verify_with_sha256(const string & message, const string & signature, RSA * p_rsa)
{
    unsigned char * sig = NULL;
    size_t sig_len = 0;
    base64_decode(signature, (void**)&sig, &sig_len);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    to_sha256(message, digest);
 
    int rc = RSA_verify(NID_sha256, digest, sizeof digest, sig, sig_len, p_rsa);
    if (1 != rc) {
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        fprintf(stderr, "Verification failed [%s]\n", errBuf);
    }

    free(sig);

    return rc;
}

static
void random_str(size_t len, char *output)
{
    unsigned char a[len];
    if (RAND_bytes(a, len))
    {
        for (size_t i = 0; i < len; i++)
        {
            sprintf(output + i * 2, "%02x", a[i]);
        }
    
    }
}

static
void parse_json_value(const char *src, size_t len, string & result)
{
    char buf[len+1];
    memset(buf, 0, len+1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if ((i == 0 || src[i-1] != '\\') && src[i] == '\\' && src[i+1] == '"')
            i++;
        buf[j++] = src[i];
    }
    result = string(buf);
}

static
size_t write_memory(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    MemChunk *mem = (MemChunk *)userp;

    mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if(mem->memory == NULL)
    {
        /* out of memory! */ 
        fprintf(stderr, "not enough memory (realloc returned NULL)\n");
        return 0;
    }
 
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
 
    return realsize;
}

static
void compose_form(struct curl_httppost ** post,
    const string & timestamp, const string & nonce, const string & signature,
    const vector<string> & images, const vector<string> & tags)
{
    struct curl_httppost* last = NULL;
    curl_formadd(post, &last,
               CURLFORM_COPYNAME, "timestamp",
               CURLFORM_COPYCONTENTS, timestamp.c_str(),
               CURLFORM_END);
    curl_formadd(post, &last,
               CURLFORM_COPYNAME, "nonce",
               CURLFORM_COPYCONTENTS, nonce.c_str(),
               CURLFORM_END);
    curl_formadd(post, &last,
               CURLFORM_COPYNAME, "signature",
               CURLFORM_COPYCONTENTS, signature.c_str(),
               CURLFORM_END);

    unsigned int i = 0;
    const char * tag = NULL;
    do
    {
        const char* img = images[i].c_str();
        if (img[0] == '@')
        {
            //Upload file with file path
            img++; //trim starting symbol '@''
            curl_formadd(post, &last,
               CURLFORM_COPYNAME, "image",
               //CURLFORM_FILENAME, "xxx",
               //CURLFORM_CONTENTTYPE, "application/octet-stream",
               CURLFORM_FILE, img,
               CURLFORM_END);
        }
        else
        {
            //File URL
            curl_formadd(post, &last,
               CURLFORM_COPYNAME, "image",
               CURLFORM_COPYCONTENTS, img,
               CURLFORM_END);
        }

        if (i < tags.size())
            tag = tags[i].c_str();
        if (NULL != tag) {
            //Set tag for the image
            curl_formadd(post, &last,
               CURLFORM_COPYNAME, "tag",
               CURLFORM_COPYCONTENTS, tag,
               CURLFORM_END);
        }
    } while (++i < images.size());
}



#if VERB_LEV >= 2
static
void dump(const char *text, FILE *stream, unsigned char *ptr, size_t size)
{
    size_t i;
    size_t c;
    unsigned int width = 0x10;

    fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size, (long)size);

    for (i = 0; i < size; i += width)
    {
        fprintf(stream, "%4.4lx: ", (long)i);

        /* show hex to the left */
        for(c = 0; c < width; c++)
        {
            if(i+c < size)
                fprintf(stream, "%02x ", ptr[i+c]);
            else
                fputs("   ", stream);
        }

        /* show data on the right */
        for (c = 0; (c < width) && (i+c < size); c++)
        {
            char x = (ptr[i+c] >= 0x20 && ptr[i+c] < 0x80) ? ptr[i+c] : '.';
            fputc(x, stream);
        }

        fputc('\n', stream); /* newline */
    }
}

static
int debug_trace(CURL *curl, curl_infotype type, char *data, size_t size, void *userptr)
{
    const char *text;
    (void)curl; /* prevent compiler warning */

    switch (type) {
        case CURLINFO_TEXT:
            fprintf(stderr, "== Info: %s", data);
        default: /* in case a new one is introduced to shock us */
            return 0;

        case CURLINFO_HEADER_OUT:
            text = "=> Send header";
            break;
        case CURLINFO_DATA_OUT:
            text = "=> Send data";
            break;
        case CURLINFO_SSL_DATA_OUT:
            text = "=> Send SSL data";
            break;
        case CURLINFO_HEADER_IN:
            text = "<= Recv header";
            break;
        case CURLINFO_DATA_IN:
            text = "<= Recv data";
            break;
        case CURLINFO_SSL_DATA_IN:
            text = "<= Recv SSL data";
            break;
    }
 
  dump(text, stderr, (unsigned char *)data, size);
  return 0;
}
#endif //VERB_LEV >= 2


} //namespace TUPU
