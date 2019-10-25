/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#ifndef __TUPU_RECOGNITION_H__
#define __TUPU_RECOGNITION_H__

#include "curl/curl.h"
#include <map>
#include <memory>
#include <iostream>
#include <string>
#include <iomanip>

namespace TUPU
{

class TImage;
typedef struct rsa_st RSA;

const char * opErrorString(int err);


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

        void setParameter(std::map<std::string, std::string> param) {m_param = param;}

        void setCid(std::string value) {m_param["CID"] = value;}

        std::string getCid() { return m_param["CID"]; }

    public:
        int performWithURL(const std::string & secretId,
            std::string & result, long *statusCode,
            const std::vector<std::string> & imageURLs,
            const std::vector<std::string> & tags = std::vector<std::string>() );

        int performWithPath(const std::string & secretId,
            std::string & result, long *statusCode,
            const std::vector<std::string> & imagePaths,
            const std::vector<std::string> & tags = std::vector<std::string>() );

        //Don't mix the use of URL and path/binary
        int perform(const std::string & secretId, const std::vector<std::shared_ptr<TImage>> & images,
                std::string & result, long *statusCode);

    private:
        void generalInit(const std::string & rsaPrivateKeyPath);

        int sendRequest(CURL *curl, curl_mime *form, const std::string & secretId,
                        std::string & result, long *statusCode);
        int handleResponse(const char * resp, size_t resp_len, std::string & result);

    private:
        //RSA * m_rsaPrivateKey;
        RSA * m_tupuPublicKey;
        std::string m_apiUrl;
        std::string m_uid;
        std::string m_ua;
        std::map<std::string, std::string> m_param;
        char * m_priKeyBuf;
}; //Class Recognition

} //namespace TUPU

#endif /* __TUPU_RECOGNITION_H__ */