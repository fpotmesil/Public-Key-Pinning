
#include "Base64.h"
#include "HashFunctions.h"
#include "CertificateFunctions.h"
#include "CertificateHashUtility.h"


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
    base64PUBKEY_ = Base64Encode(hashed);

    std::cout << "The base64 encoded X509_PUBKEY structure is " 
        << base64PUBKEY_.length() << " bytes: " << base64PUBKEY_ << std::endl;

    parseCertificateSAN( cert_, sanName_ );
    parseCertificateCommonName( cert_, commonName_ );
}

//
// this should prefer the SAN field if there is one.
// The Common Name field is deprecated.
// However, for my purposes, for my very simple demo application, the Common Name
// will be present and accounted for.  So I will just use that.  Really I only
// want one name to be used as a map key anyway.
//
void CertificateHashUtility::writeCertificateHashInfo( const std::string & outFileName )
{
    std::ofstream fout(outFileName.c_str(), std::ios::out|std::ios::app);
    
    if( fout.good() )
    {
        fout << commonName_ << " " << base64PUBKEY_ << std::endl;
        fout.close();
    }
    else
    {
        std::cout << "Error opening " << outFileName << ": " << strerror(errno) << std::endl;
    }
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


