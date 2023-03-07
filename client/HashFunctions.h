#ifndef HASH_FUNCTIONS_H__
#define HASH_FUNCTIONS_H__

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>

bool computeHash(
        const std::string & unhashed,
        std::string & hashed);
// std::string sha256(const std::string str);


#endif      /*  #define HASH_FUNCTIONS_H__  */
