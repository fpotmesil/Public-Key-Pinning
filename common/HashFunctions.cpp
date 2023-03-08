//
// simple hashing functions using OpenSSL interface
// https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
//

#include <fstream>
#include <string.h>
#include <errno.h>

#include "HashFunctions.h"
#if 0
//
// SHA256 deprecated with OpenSSL 3!
//
std::string sha256(const std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}
#endif

bool computeHash(const std::string& unhashed, std::string& hashed)
{
    bool success = false;

    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if(context != NULL)
    {
        if(EVP_DigestInit_ex(context, EVP_sha512(), NULL))
        {
            if(EVP_DigestUpdate(context, unhashed.c_str(), unhashed.length()))
            {
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int lengthOfHash = 0;

                if(EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    std::stringstream ss;
                    for(unsigned int i = 0; i < lengthOfHash; ++i)
                    {
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }

                    hashed = ss.str();
                    success = true;
                }
            }
        }

        EVP_MD_CTX_free(context);
    }

    return success;
}

void populateAcceptableConnectionsMap( 
        const std::string & inputFileName,
        std::map<std::string, std::string> & hostsMap )
{
    std::ifstream fin(inputFileName.c_str(), std::ifstream::in);

    if( !fin.good() )
    {
        std::cout << __func__ << ": Error opening " << inputFileName
            << ": " << strerror(errno) << std::endl;
    }
    else
    {
        std::string line;
        std::string hostName;
        std::string hashValue;

        while( std::getline(fin, line) )
        {
            std::istringstream iss(line);

            if( !(iss >> hostName >> hashValue) )
            {
                break;
            }

            auto rval = hostsMap.insert( 
                    std::make_pair(hostName,hashValue) );

            if( rval.second )
            {
                std::cout << "Inserted hostname " << hostName 
                    << " into acceptable host map. " << std::endl;
            }
            else
            {
                //
                // Error!   this indicates a duplicate key entry!
                //
                std::cout << "Acceptable host map insert error for hostname: "
                    << hostName << std::endl;
            }
        }

        fin.close();
    }
}


