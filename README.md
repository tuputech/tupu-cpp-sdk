# TUPU C++ SDK

SDK for TUPU visual recognition service
######  
<https://www.tuputech.com>

## Changelogs
#### v1.2.1
- Update usage and example

#### v1.2
- Correct examples for not mixing url and path in one request

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
    string secretId = "your_secret_id"
    Recognition *rec = new Recognition("Path-of-Your-PKCS8-Private-Key");

    //Set sub-user identifier for billing and statistics (optional feature)
    //rec->setUID("user-bucket-xyz");

    string imgUrl = "http://www.yourdomain.com/img/1.jpg"
    string imgPath1 = "/home/user/img/1.jpg"
    string imgPath2 = "/home/user/img/2.jpg"

    vector<string> images1 = { imgUrl };
    vector<string> images2 = { imgPath1, imgPath2 };
    vector<string> tags = {"Funny"}; //number of tags may be less than number of images

    string result;
    long statusCode = 0;
    OpCode rc = OPC_OK;

    //Providing URLs of images with tags (optional)
    rc = rec->performWithURL(secretId, result, &statusCode, images1, tags);
    printResult(rc, statusCode, result);

    //Providing paths of images without tags (optional)
    rc = rec->performWithPath(secretId, result, &statusCode, images2);
    printResult(rc, statusCode, result);

    //Providing image binary and path
    vector<TImage> images3;
    loadImage(images3, imgPath2.c_str(), "Room102");
    TImage timg;
    timg.setPath(imgPath1);
    timg.setTag("Room103");
    images3.push_back(timg);
    rc = rec->perform(secretId, images3, result, &statusCode);
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

---------------

## Recognition::performWithURL

Perform a synchronous(blocking model) API call with URLs of images. This method can be called multiple times simultaneously.

#### Parameters
- **secretId**: user's secret-id for accessing the API
- **result**: recognition result in JSON string from server
- **statusCode**: status code of response
- **imageURLs**: list of image URLs
- **tags**: list of tags for images (optional)

#### Return Values

Returns OPC_OK on success.

---------------

## Recognition::performWithPath

Perform a synchronous(blocking model) API call with local path of images. This method can be called multiple times simultaneously.

#### Parameters
- **secretId**: user's secret-id for accessing the API
- **result**: recognition result in JSON string from server
- **statusCode**: status code of response
- **imagePaths**: list of image local paths
- **tags**: list of tags for images (optional)

#### Return Values

Returns OPC_OK on success.

---------------

## Recognition::perform

Perform a synchronous API call and functions like the other 2 performXXX, but it also supports image binary.

### NOTES:
- Please don't mix use of URL and path/binary in ONE call
- If using tag, please set tag for all images

#### Parameters
- **secretId**: user's secret-id for accessing the API
- **images**: list of TImage objects
- **result**: recognition result in JSON string from server
- **statusCode**: status code of response
#### Return Values

Returns OPC_OK on success.

## License

[MIT](http://www.opensource.org/licenses/mit-license.php)
