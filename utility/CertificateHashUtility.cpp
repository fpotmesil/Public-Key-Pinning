
#include <fstream>
#include <sstream>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <vector>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "Base64.h"
#include "HashFunctions.h"
#include "CertificateHashUtility.h"

void pkp_display_error(const char* msg, long err)
{
    if(err == 0x14090086)
        fprintf(stderr, "Error: %s: SSL3_GET_SERVER_CERTIFICATE: certificate verify failed (%ld, %lx)\n", msg, err, err);
    else if (err == 0)
        fprintf(stderr, "Error: %s\n", msg);
    else if(err < 10)
        fprintf(stderr, "Error: %s: %ld\n", msg, err);
    else
        fprintf(stderr, "Error: %s: %ld (%lx)\n", msg, err, err);
}

void pkp_display_warning(const char* msg, long err)
{
    if(err < 10)
        fprintf(stdout, "Warning: %s: %ld\n", msg, err);
    else
        fprintf(stdout, "Warning: %s: %ld (%lx)\n", msg, err, err);
}

void CertificateHashUtility::pkp_print_cn_name(
        const char* label,
        X509_NAME* const name,
        int nid,
        std::string & value )
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, nid, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "  %s: %s\n", label, utf8);
        value.assign((char*)utf8,length);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
    {
        value = "";
        fprintf(stdout, "  %s: <not available>\n", label);
    }
}

void CertificateHashUtility::pkp_print_san_name(
        const char * label,
        X509* const cert, 
        int nid,
        std::string & value )
{
    unsigned char* utf8 = NULL;
    int success = 0;
    
    do
    {
        GENERAL_NAMES* names = NULL;
        
        names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, nid, 0, 0 );
        if(!names) break;
        
        int i = 0, numAN = sk_GENERAL_NAME_num(names);
        if(!numAN) break; /* failed */
        
        for( i = 0; i < numAN; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = 0;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    /* Moxie Marlinspike is in the room .... */
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded nul?): %d vs %d\n", len2, len1);
                    
                }
                
                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) 
                {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    value.assign((char*)utf8,len2);
                    success = 1;
                }
                
                if(utf8) 
                {
                    OPENSSL_free(utf8);
                    utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
    {
        value = "";
        fprintf(stdout, "  %s: <not available>\n", label);
    }
    
}

CertificateHashUtility::CertificateHashUtility(
        const std::string & myCertFile ) : localCertFile_(myCertFile)
{ }


void CertificateHashUtility::generateCertificateHash( void )
{
    //
    // readCertificate checks cert for NULL before returning.
    //
    readCertificate( localCertFile_ );
    //
    // first step is to get the DER format of the Public Key.
    //
    // X509_get_X509_PUBKEY() returns an internal pointer to the 
    // X509_PUBKEY structure which encodes the certificate of x. 
    // The returned value must not be freed up after use.
    //
    // The X509_PUBKEY structure represents the ASN.1 SubjectPublicKeyInfo 
    // structure defined in RFC5280 and used in certificates and certificate requests.
    //
    // i2d_TYPE() encodes the structure pointed to by a into DER format.
    //
    // If ppout is not NULL, it writes the DER encoded data to the buffer 
    // at *ppout, and increments it to point after the data just written.
    // If the return value is negative an error occurred, otherwise it 
    // returns the length of the encoded data.
    //
    // If *ppout is NULL memory will be allocated for a buffer and the encoded 
    // data written to it. In this case *ppout is not incremented and it points
    // to the start of the data just written.
    //
    unsigned char * pubKeyBuffer = NULL;
    int pubKeyLen = i2d_X509_PUBKEY( X509_get_X509_PUBKEY(cert_), &pubKeyBuffer );
    long ssl_err = ERR_get_error();

    if( pubKeyLen <= 0 )
    {
        if( pubKeyBuffer != NULL ) OPENSSL_free(pubKeyBuffer);
        std::ostringstream error;
        error << "i2d_X509_PUBKEY Error: [" << ssl_err << "]" << std::endl;
        throw std::runtime_error(error.str());  // better catch this!
    }

    std::cout << "The DER encoded X509_PUBKEY structure is " 
        << pubKeyLen << " bytes." << std::endl;

    //
    // next step is to SHA512 our DER encoded X509_PUBKEY structure in pubKeyBuffer
    //
    std::string input((char*)pubKeyBuffer, pubKeyLen);
    if( pubKeyBuffer != NULL ) OPENSSL_free(pubKeyBuffer);
    std::string hashedPUBKEY;
    
    if( !computeHash(input,hashedPUBKEY) )
    {
        std::ostringstream error;
        error << "Error computing hash for DER encoded X509_PUBKEY structure." << std::endl;
        throw std::runtime_error(error.str());  // better catch this!
    }

    //
    // next step is to base64 encode our hashed DER encoded X509_PUBKEY string value.
    //
    std::vector<unsigned char> hashed(hashedPUBKEY.begin(), hashedPUBKEY.end());
    std::string base64PUBKEY = Base64Encode(hashed);

    std::cout << "The base64 encoded X509_PUBKEY structure is " 
        << base64PUBKEY.length() << " bytes: " << base64PUBKEY << std::endl;
}
void CertificateHashUtility::parseCertificateSAN( void )
{
    /* Print the SAN field if present */
    pkp_print_san_name("Subject (san)", cert_, /*sname,*/ NID_subject_alt_name, sanName_);
}

void CertificateHashUtility::parseCertificateIssuerName( void )
{
    X509_NAME * iname = X509_get_issuer_name(cert_);
    
    std::string value;
    /* Issuer is the authority we trust that warrants nothing useful */
    pkp_print_cn_name("Issuer (cn)", iname, NID_commonName, value);
}


void CertificateHashUtility::parseCertificateCommonName( void )
{
    X509_NAME * sname = X509_get_subject_name(cert_);
    
    std::string value;
    /* Subject is who the certificate is issued to by the authority  */
    pkp_print_cn_name("Subject (cn)", sname, NID_commonName, commonName_);
}

void CertificateHashUtility::writeCertificateHash( const std::string & outFileName )
{
    (void)outFileName;
    //
    // FJP TODO
    //
}

X509 * CertificateHashUtility::readCertificate( const std::string & certFileName )
{
	BIO * fileBio = BIO_new_file(certFileName.c_str(), "r");

    if( NULL == fileBio ) 
    {
        std::ostringstream error;
        error << "BIO_new_file Error opening: " << certFileName << ": "
            << strerror(errno) << std::endl;
        throw std::runtime_error(error.str());
    }

	cert_ = PEM_read_bio_X509(fileBio, NULL, NULL, NULL);
	BIO_free(fileBio);

    if( NULL == cert_ ) 
    {
        std::ostringstream error;
        error << "PEM_read_bio_X509 Error reading: " << certFileName << std::endl;
        throw std::runtime_error(error.str());
    }

	return cert_;
}



