/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#ifndef __TUPU_RECOGNITION_H__
#define __TUPU_RECOGNITION_H__

namespace TUPU
{

class TImage;
typedef struct rsa_st RSA;

typedef enum {
    OPC_OK = 0,
    OPC_WRONGPARAM = 1, //Wrong parameter(s)
    OPC_SIGNFAILED = 2, //Failed to sign request
    OPC_SENDFAILED = 3, //Failed to send request
    OPC_REQFAILED = 4, //Request failed
    OPC_PARSEFAILED = 5, //Failed t parse response data
    OPC_VERIFYFAILED = 6, //Failed to verify response signature
    OPC_OTHERS = 10
} OpCode;

class Recognition
{
    public:
        Recognition(const std::string & rsaPrivateKeyPath);
        Recognition(const std::string & rsaPrivateKeyPath, const std::string & apiUrl);
        virtual ~Recognition();

    public:
        //Set uid post paremeter to identify sub-users
        void setUID(const std::string & uid) { m_uid = uid; }
        //Set user-agent of request(s)
        void setUserAgent(const std::string & ua) { m_ua = ua; }

    public:
        OpCode perform(const std::string & secretId, const std::vector<TImage> & images,
            std::string & result, long *statusCode);

#if __cplusplus >= 201103L
        OpCode perform(const std::string & secretId,
            std::string & result, long *statusCode,
            const std::vector<std::string> & images,
            const std::vector<std::string> & tags = {} );
#else //c++98
        OpCode perform(const std::string & secretId,
            std::string & result, long *statusCode,
            const std::vector<std::string> & images,
            const std::vector<std::string> & tags = std::vector<std::string>() );
#endif

    private:
        void generalInit(const std::string & rsaPrivateKeyPath);
        OpCode sendRequest(const std::string & secretId, struct curl_httppost *post,
            std::string & result, long *statusCode );
        OpCode handleResponse(const char * resp, size_t resp_len, std::string & result);

    private:
        RSA * m_rsaPrivateKey;
        RSA * m_tupuPublicKey;
        std::string m_apiUrl;
        std::string m_uid;
        std::string m_ua;
}; //Class Recognition

} //namespace TUPU

#endif /* __TUPU_RECOGNITION_H__ */