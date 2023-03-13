//
// This started from example file server.cpp
// ~~~~~~~~~~
//
// https://www.boost.org/doc/libs/1_81_0/doc/html/boost_asio/example/cpp11/ssl/server.cpp
//
// Copyright (c) 2003-2022 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>


#include "Base64.h"
#include "HashFunctions.h"
#include "CertificateFunctions.h"
#include "BoostAsioSslSession.h"


///@brief Helper class that prints the current certificate's subject
///       name and the verification results.
// https://stackoverflow.com/questions/28264313/ssl-certificates-and-boost-asio
//
template <typename Verifier>
class verbose_verification
{
public:
  verbose_verification(Verifier verifier)
    : verifier_(verifier)
  {}

  bool operator()(
    bool preverified,
    boost::asio::ssl::verify_context& ctx )
  {
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

    char subject_name[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);

    char issuer_name[256];
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer_name, 256);

    bool verified = verifier_(preverified, ctx);

    std::cout << "\nCertificate Issuer Name: " << issuer_name << std::endl; 
    std::cout << "Verifying Subject: " << subject_name 
        << (verified ? ": Passed " : ": Failed ") << std::endl;

    return verified;
  }
private:
  Verifier verifier_;
};

///@brief Auxiliary function to make verbose_verification objects.
template <typename Verifier>
verbose_verification<Verifier>
make_verbose_verification(Verifier verifier)
{
  return verbose_verification<Verifier>(verifier);
}

BoostAsioSslSession::BoostAsioSslSession(
            tcp::socket socket,
            boost::asio::ssl::context & ctx,
            const std::string & remoteHostname,
            const std::map<std::string,std::string> & pinnedHostsMap ) :
            // const std::string & hashDataFile ) :
    socket_( std::move(socket), ctx ),
    context_(ctx),
    remoteEndpoint_(socket_.lowest_layer().remote_endpoint()),
    remoteHostname_(remoteHostname),
    pinnedHostsMap_(pinnedHostsMap)
{
    std::cout << "In BoostAsioSslSession Constructor.  Remote Host is: " 
        << remoteHostname_ << " at IP " << remoteEndpoint_.address().to_string() 
        << std::endl;

   socket_.set_verify_mode(
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_fail_if_no_peer_cert);
#if 1
    //
    // https://www.boost.org/doc/libs/1_81_0/boost/asio/ssl/host_name_verification.hpp
    //
    // Boost host_name_verification verifies a certificate against a host_name
    // according to the rules described in RFC 6125.
    //
    // Boost rfc2818 verification is based off rules in RFC 2818.  Prefer to use
    // the 'more strict' host_name_verification if present.  This was added in 
    // Boost version 1.73.0 so it might not be available depending on OS flavor and version.
    //
    // FJP TODO - fix this so it uses BOOST_VERSION instead of crappy if 1/else
    //
    socket_.set_verify_callback(
		    make_verbose_verification(
#if 1
                boost::asio::ssl::host_name_verification(remoteHostname_.c_str())));
#else
			    boost::asio::ssl::rfc2818_verification(remoteHostname_.c_str())));
#endif
#else
    //
    // This verify_certificate callback just dumps out the subject names
    // and is really only for debugging.
    //
    std::bind(&BoostAsioSslSession::verify_certificate, this, _1, _2);
#endif
}


// comment from owasp site code:
/* Extra hardening so we can discard DNS and CA hearsay. If we   */
/* pin, we can pretty much skip the tests in 'Part 6a: Verify'   */
/* and 'Part 6b: Verify' since we can unequivocally identify     */
/* the host through its public key.                              */
//
/***************************************************************************/
/* Fetch the certificate from the website, extract the public key as a     */
/* DER encoded subjectPublicKeyInfo, and then compare it to the public key */
/* on file. The key on file is what we expect to get from the server.      */
/* lots of this code from owasp pkp_pin_peer_pubkey(SSL* ssl) function     */
/***************************************************************************/
bool BoostAsioSslSession::checkPinnedPublicKey( void )
{
    /* http://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html */
    X509 * cert = SSL_get_peer_certificate(socket_.native_handle());
    long ssl_err = ERR_get_error();
    bool rval = false;

    if( NULL == cert ) 
    {
        std::ostringstream error;
        error << "SSL_get_peer_certificate Error: [" << ssl_err << "]" << std::endl;
        throw std::runtime_error(error.str());  // better catch this!
    }

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
    int pubKeyLen = i2d_X509_PUBKEY( X509_get_X509_PUBKEY(cert), &pubKeyBuffer );
    ssl_err = (long)ERR_get_error();

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

    //
    // FJP TODO:  get the common name and check the map!!
    //
    parseCertificateSAN( cert, sanName_ );
    parseCertificateCommonName( cert, commonName_ );

    rval = checkPinnedSpkiMap( commonName_, base64PUBKEY, pinnedHostsMap_ );

    /* http://www.openssl.org/docs/crypto/X509_new.html */
    if(NULL != cert)
        X509_free(cert);

    return rval;
}

void BoostAsioSslSession::do_handshake( void )
{
    auto self(shared_from_this());

	std::cout << "Server starting SSL/TLS handshake now...."
				<< std::endl;

    socket_.async_handshake(boost::asio::ssl::stream_base::server, 
        [this, self](const boost::system::error_code& error)
        {
		    if (!error)
            {
                // SSL * ssl = socket_.native_handle();
                // (void)ssl; // for now to get rid of error warning
                /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
                /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
                long res = SSL_get_verify_result(socket_.native_handle());

                if(X509_V_OK == res)
                {
                    if( checkPinnedPublicKey() )
                    {
                        std::cout << __func__ << ": Pinned SPKI hash data checks passed!" 
                            << std::endl;

                        do_read();
                    }
                    else
                    {
                        std::cout << __func__ << ": Pinned SPKI data checks failed!" 
                            << std::endl;
                    }
                }
                else
                {
                    std::cerr << "SSL_get_verify_result failed. [" << res << "]  Exiting. "
                        << std::endl;
                }
            }
            else
            {
			    std::cout << "TLS handshake ERROR from " 
                    << remoteHostname_ << " at IP " << remoteEndpoint_.address().to_string() 
                    << std::endl;
            }
        });
}

void BoostAsioSslSession::do_read( void )
{
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_),
        [this, self](const boost::system::error_code& ec, std::size_t length)
        {
            if (!ec)
            {
                do_write(length);
            }
        });
}

void BoostAsioSslSession::do_write(std::size_t length)
{
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(data_, length),
        [this, self](const boost::system::error_code& ec,
                std::size_t /*length*/)
        {
            if (!ec)
            {
                do_read();
            }
        });
}


