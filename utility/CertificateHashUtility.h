#ifndef CERTIFICATE_HASH_UTILITY_H__
#define CERTIFICATE_HASH_UTILITY_H__

#include <fstream>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <vector>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>


class CertificateHashUtility
{
    public:
        CertificateHashUtility( const std::string & myCertFile );
        void generateCertificateHash( void );
        void writeCertificateHashInfo( const std::string & outFileName );

        void cleanup( void )
        {
            X509_free(cert_);
            cert_ = NULL;
        }

    private:
        X509 * readCertificate( const std::string & certFileName );
        const std::string localCertFile_;
        std::string base64PUBKEY_;
        std::string commonName_;
        std::string sanName_;
        X509 * cert_ = NULL;
};


#endif  /* #define CERTIFICATE_HASH_UTILITY  */
