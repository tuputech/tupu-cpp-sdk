/******************************************************************************
 * TUPU Recognition API SDK
 * Copyright(c)2013-2016, TUPU Technology
 * http://www.tuputech.com
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/stat.h>
#include <vector>

#include "Base64.hpp"
#include "Recognition.hpp"

using namespace std;
using namespace TUPU;

int main(int argc, char *argv[]) {
    Recognition *rec = new Recognition("Path-of-Your-PKCS8-Private-Key");

    vector<string> images = {
        "http://www.yourdomain.com/img/1.jpg" //providing a remote url of image
        , "@/home/user/img/2.jpg" //providing a local file path to upload
    };
    vector<string> tags = {"Funny"}; //number of tags may be less than number of images

    string result;
    long statusCode = 0;
    OpCode rc;
    rc = rec->perform("your_secret_id", result, &statusCode, images, tags);
    //ingore tags of images
    //rc = rec->perform("your_secret_id", result, &statusCode, images);

    cout << "- Perform returns: " << rc << endl;
    cout << "- HTTP Status Code: " << statusCode << endl;
    cout << "- Result: " << endl << result << endl;

    delete rec;

    return 0;
}





