//
// Simple Base64 Encode and Decode using OpenSSL BIOs
// https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl/33331627#33331627
//

#include "Base64.h"

#if 0
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <iostream>


namespace 
{
    struct BIOFreeAll { void operator()(BIO* p) { BIO_free_all(p); } };
}
#endif

std::string Base64Encode(const std::vector<unsigned char>& binary)
{
    std::unique_ptr<BIO,BIOFreeAll> b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* sink = BIO_new(BIO_s_mem());
    BIO_push(b64.get(), sink);
    BIO_write(b64.get(), binary.data(), binary.size());
    (void)BIO_flush(b64.get());
    const char* encoded;
    const long len = BIO_get_mem_data(sink, &encoded);
    return std::string(encoded, len);
}

// Assumes no newlines or extra characters in encoded string
std::vector<unsigned char> Base64Decode(const char* encoded)
{
    std::unique_ptr<BIO,BIOFreeAll> b64(BIO_new(BIO_f_base64()));
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* source = BIO_new_mem_buf(encoded, -1); // read-only source
    BIO_push(b64.get(), source);
    const int maxlen = strlen(encoded) / 4 * 3 + 1;
    std::vector<unsigned char> decoded(maxlen);
    const int len = BIO_read(b64.get(), decoded.data(), maxlen);
    decoded.resize(len);
    return decoded;
}

#if 0
//
// test application
//
int main()
{
    const char* msg = "hello";
    const std::vector<unsigned char> binary(msg, msg+strlen(msg));
    const std::string encoded = Base64Encode(binary);
    std::cout << "encoded = " << encoded << std::endl;
    const std::vector<unsigned char> decoded = Base64Decode(encoded.c_str());
    std::cout << "decoded = ";
    for (unsigned char c : decoded) std::cout << c;
    std::cout << std::endl;
    return 0;
}
#endif
