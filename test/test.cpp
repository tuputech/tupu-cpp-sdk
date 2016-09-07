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

#include "Base64.hpp"
#include "TImage.hpp"
#include "Recognition.hpp"

using namespace std;
using namespace TUPU;

void loadImage(vector<TImage> & images, const char * path, const char * tag = NULL);
void printResult(OpCode rc, long statusCode, const string & result);


int main(int argc, char *argv[]) {
    Recognition *rec = new Recognition("Path-of-Your-PKCS8-Private-Key");

    //Set sub-user identifier for billing and statistics (optional feature)
    //rec->setUID("user-bucket-xyz");

    string imgUrl = "http://www.yourdomain.com/img/1.jpg"
    string imgPath = "@/home/user/img/2.jpg"

    vector<string> images = {
        imgUrl //providing a remote url of image
        , "@" + imgPath //providing a local file path to upload
    };
    vector<string> tags = {"Funny"}; //number of tags may be less than number of images

    string result;
    long statusCode = 0;
    OpCode rc = OPC_OK;
    string secretId = "your_secret_id"

    //Providing URLs or paths of images with tags
    rc = rec->perform(secretId, result, &statusCode, images, tags);
    printResult(rc, statusCode, result);

    //Ingore tags of images
    rc = rec->perform(secretId, result, &statusCode, images);
    printResult(rc, statusCode, result);

    //Providing image binary and URL
    vector<TImage> timages;
    loadImage(timages, imgPath.c_str(), "Amazing");
    TImage timg;
    timg.setURL(imgUrl);
    timages.push_back(timg);
    rc = rec->perform(secretId, timages, result, &statusCode);
    printResult(rc, statusCode, result);

    delete rec;

    return 0;
}


void loadImage(vector<TImage> & images, const char * path, const char * tag)
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

        TImage img;
        img.setBinary(buffer, length, fn);
        if (tag != NULL)
            img.setTag(tag);
        images.push_back(img);

        delete buffer;
    }
    f.close();
}

void printResult(OpCode rc, long statusCode, const string & result)
{
    cout << "- Perform returns: " << rc << endl;
    cout << "- HTTP Status Code: " << statusCode << endl;
    cout << "- Result: " << endl << result << endl;
}


