# TUPU C++ SDK

SDK for TUPU visual recognition service
######  
<https://www.tuputech.com>


## Requirements

- openssl & openssl-devel (openssl-dev)
- libcurl & libcurl-devel (libcurl-dev)
- cmake


## Building

\$ cmake .
\$ make

#### Output

- lib/libtupu.a
- lib/libtupu.so

## Example

```
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
```

## Method perform

Perform a synchronous API call

#### Parameters
- **secretId**: user's secret-id for accessing the API
- **result**: recognition result in JSON string from server
- **statusCode**: status code of response
- **images**: list of image URLs or Paths (path starts with '@')
- **tags**: list of tags for images (optional)

#### Return Values

Returns OPC_OK on success.

## License

[MIT](http://www.opensource.org/licenses/mit-license.php)
