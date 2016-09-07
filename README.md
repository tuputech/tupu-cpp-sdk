# TUPU C++ SDK

SDK for TUPU visual recognition service
######  
<https://www.tuputech.com>

## Changelogs
#### v1.1
- Supporting binary image data
- Add uid parameter 

## Requirements

- openssl & openssl-devel (openssl-dev)
- libcurl & libcurl-devel (libcurl-dev)
- cmake


## Building

```
    $ cmake .
    $ make
```

#### Output

- lib/libtupu.a
- lib/libtupu.so

## Example

```
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
```

## Method perform

Perform a synchronous API call

**NOTE: This method can be called multiple times simultaneously, and it's recommended to use ONE SINGLE Recognition object for multiple threads.**

#### Parameters of entry 1
- **secretId**: user's secret-id for accessing the API
- **images**: list of TImage objects
- **result**: recognition result in JSON string from server
- **statusCode**: status code of response

#### Parameters of entry 2
- **secretId**: user's secret-id for accessing the API
- **result**: recognition result in JSON string from server
- **statusCode**: status code of response
- **images**: list of image URLs or Paths (path starts with '@')
- **tags**: list of tags for images (optional)

#### Return Values

Returns OPC_OK on success.

## License

[MIT](http://www.opensource.org/licenses/mit-license.php)
