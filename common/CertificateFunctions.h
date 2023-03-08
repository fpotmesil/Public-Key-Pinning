#ifndef CERTIFICATE_FUNCTIONS_H__
#define CERTIFICATE_FUNCTIONS_H__

#include <map>
#include <string>
#include <iostream>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void parseCertificateSAN( 
        const X509 * cert,
        std::string & value );

void parseCertificateIssuerName( 
        const X509 * const cert,
        std::string & value );

void parseCertificateCommonName( 
        const X509 * cert, 
        std::string & value );

bool checkPinnedSpkiMap( 
        const std::string & commonName,
        const std::string & base64PUBKEY,
        const std::map<std::string, std::string> & pinnedHostsMap );


//
// functions with name prefix 'pkp_' were taken from OWASP PKP examples at
// https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
//
void pkp_print_san_name(
        const char * label,
        const X509* const cert, 
        int nid,
        std::string & value);

void pkp_print_cn_name(
        const char* label,
        X509_NAME* const name,
        int nid,
        std::string & value);



#endif  /* #define CERTIFICATE_FUNCTIONS_H__ */
