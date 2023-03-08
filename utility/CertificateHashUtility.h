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
        void writeCertificateHash( const std::string & outFileName );

        //
        // functions with name prefix 'pkp_' were taken from OWASP PKP examples at
        // https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
        //
        static void pkp_print_san_name(
                const char * label,
                X509* const cert, 
                int nid);

        static void pkp_print_cn_name(
                const char* label,
                X509_NAME* const name,
                int nid);

        static int pkp_verify_cb(
                int preverify, 
                X509_STORE_CTX * x509_ctx );

    private:
        X509 * readCertificate( const std::string & certFileName );

        bool verify_certificate(
                bool preverified,
                boost::asio::ssl::verify_context& ctx);

        void checkPinnedPublicKey( void );

        const std::string localCertFile_;
};


#endif  /* #define CERTIFICATE_HASH_UTILITY  */
