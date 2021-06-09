/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <vector>
#include <time.h>
#include <sys/time.h>

#include "Base64.hpp"
#include "TImage.hpp"
#include "Recognition.hpp"

using namespace std;
using namespace TUPU;

void loadImage(vector<shared_ptr<TImage>> & images, const char * path, const char * tag = NULL);
void printResult(int rc, long statusCode, const string & result, long start);
long getTime();


int main(int argc, char *argv[]) {
    string secretId = "your_secret_id";
    Recognition *rec = new Recognition("Path-of-Your-PKCS8-Private-Key");

    //Set sub-user identifier for billing and statistics (optional feature)
    // int rs = rec->setUID("user-bucket-xyz");
    // if (rs != 0) {
    //     return rs;
    // }

    string result;
    long statusCode = 0;
    int rc = 0;
    vector<string> tags = {"Funny", "kkk"}; //number of tags may be less than number of images
    long start = getTime();

    /*********** imageUrl *****************/
    //Providing URLs of images with tags (optional)
    string imgUrl = "https://r.tuputech.com/original/world/data-c40/yrw/api_test_data/normal.jpg";
    vector<string> images1 = { imgUrl };
    rc = rec->performWithURL(secretId, result, &statusCode, images1, tags);
    printResult(rc, statusCode, result, start);
    /*************************************/

    /*********** imagePath *****************/
    string imgPath1 = "/home/user/img/1.jpg";
    string imgPath2 = "/home/user/img/2.jpg";
    vector<string> images2 = { imgPath1, imgPath2 };
    start = getTime();
    //Providing paths of images without tags (optional)
    rc = rec->performWithPath(secretId, result, &statusCode, images2);
    printResult(rc, statusCode, result, start);
    /*************************************/

    /*********** imageContent *****************/
    start = getTime();
    // Providing image binary and path
    string imgPath3 = "/home/user/img/2.jpg";
    vector<shared_ptr<TImage>> images3;
    loadImage(images3, imgPath3.c_str(), "Room102");
    shared_ptr<TImage> timg = std::make_shared<TImage>();
    timg->setPath(imgPath3);
    timg->setTag("Room103");
    images3.push_back(timg);
    rc = rec->perform(secretId, images3, result, &statusCode);
    printResult(rc, statusCode, result, start);
    /*************************************/

    delete rec;

    return 0;
}


void loadImage(vector<shared_ptr<TImage>> & images, const char * path, const char * tag)
{
    ifstream f;
    f.open(path, ios::binary);
    if (f.good()) {
        f.seekg(0, ios::end);
        int length = f.tellg();
        f.seekg(0, ios::beg);
        char *buffer = new char[length];
        f.read(buffer, length);

        const char *fn = strrchr(path, '/');
        fn = (fn == NULL) ? path : fn+1;

        shared_ptr<TImage> img;
        img->setBinary(buffer, length, fn);
        if (tag != NULL)
            img->setTag(tag);
        images.push_back(img);

        delete buffer;
    }
    f.close();
}

void printResult(int rc, long statusCode, const string & result, long start)
{
    cout << "- Perform returns: " << rc << " " << TUPU::opErrorString(rc) << endl;
    cout << "- HTTP Status Code: " << statusCode << endl;
    cout << "- Elapsed time: " << (getTime() - start) << "ms" << endl;
    cout << "- Result: " << endl << result << endl;
}

long getTime()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000 + tv.tv_usec/1000;
}

