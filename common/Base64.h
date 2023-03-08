#ifndef BASE64_H__
#define BASE64_H__

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

std::string Base64Encode(const std::vector<unsigned char>& binary);
std::vector<unsigned char> Base64Decode(const char* encoded);


#endif   /* #define BASE64_H__  */
