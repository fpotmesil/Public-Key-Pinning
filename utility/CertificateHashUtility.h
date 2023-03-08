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
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>


class CertificateHashUtility
{
    public:
        CertificateHashUtility( const std::string & myCertFile );
        void generateCertificateHash( void );
        void parseCertificateCommonName( void );
        void parseCertificateIssuerName( void );
        void parseCertificateSAN( void );
        void writeCertificateHashInfo( const std::string & outFileName );

        //
        // functions with name prefix 'pkp_' were taken from OWASP PKP examples at
        // https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
        //
        void pkp_print_san_name(
                const char * label,
                X509* const cert, 
                int nid,
                std::string & value);

        void pkp_print_cn_name(
                const char* label,
                X509_NAME* const name,
                int nid,
                std::string & value);

        void cleanup( void )
        {
            X509_free(cert_);
            cert_ = NULL;
        }

    private:
        X509 * readCertificate( const std::string & certFileName );

        const std::string localCertFile_;
        std::string base64PUBKEY_; // = Base64Encode(hashed);
        std::string commonName_;
        std::string sanName_;
        X509 * cert_ = NULL;
};


#endif  /* #define CERTIFICATE_HASH_UTILITY  */
