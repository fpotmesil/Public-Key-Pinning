//
// Started from Boost Example client.cpp
// https://www.boost.org/doc/libs/1_81_0/doc/html/boost_asio/example/cpp11/ssl/client.cpp
//
// Copyright (c) 2003-2022 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <sstream>

#include "Base64.h"
#include "HashFunctions.h"
#include "BoostAsioSslClient.h"
#include "BoostAsioSslClient.h"


///@brief Helper class that prints the current certificate's subject
///       name and the verification results.
// https://stackoverflow.com/questions/28264313/ssl-certificates-and-boost-asio
//
template <typename Verifier>
class verbose_verification
{
    public:
        verbose_verification(Verifier verifier)
            : verifier_(verifier) {}

        bool operator()(
                bool preverified,
                boost::asio::ssl::verify_context& ctx )
        {
            int verifyRval = BoostAsioSslClient::pkp_verify_cb(
                    preverified, ctx.native_handle() );
            std::cout << "Initial verify callback rval: " << verifyRval << std::endl;

            char subject_name[256];
            X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
            X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);

            bool verified = verifier_(preverified, ctx);
            std::cout << "Verifying: " << subject_name << "\n"
                "Verified: " << verified << std::endl;


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

void BoostAsioSslClient::pkp_print_cn_name(
        const char* label,
        X509_NAME* const name,
        int nid)
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
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
        fprintf(stdout, "  %s: <not available>\n", label);
}

void BoostAsioSslClient::pkp_print_san_name(
        const char * label,
        X509* const cert, 
        int nid)
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
                if(utf8 && len1 && len2 && (len1 == len2)) {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    success = 1;
                }
                
                if(utf8) {
                    OPENSSL_free(utf8), utf8 = NULL;
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
        fprintf(stdout, "  %s: <not available>\n", label);
    
}

/*************************************************************************/
/* `preverify` is the result of OpenSSL's internal verification. 1 is    */
/* success, and 0 is failure. The internal tests consist of customary    */
/* X509 checks, such as signature/trust chain, not before date, and not  */
/* after date.                                                           */
/*                                                                       */
/* We can ignore it if we are using public keys for identity and         */
/* authentication of the server. If we ignore, verifcation MUST occur    */
/* via pkp_pin_peer_pubkey() (Part 6 above).                             */
/*                                                                       */
/* Or we can observe it...                                               */
/*************************************************************************/
int BoostAsioSslClient::pkp_verify_cb(
        int preverify, 
        X509_STORE_CTX * x509_ctx )
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */
    
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    fprintf(stdout, "pkp_verify_cb (depth=%d)(preverify=%d)\n", depth, preverify);
    
    /* Issuer is the authority we trust that warrants nothing useful */
    pkp_print_cn_name("Issuer (cn)", iname, NID_commonName);
    
    /* Subject is who the certificate is issued to by the authority  */
    pkp_print_cn_name("Subject (cn)", sname, NID_commonName);
    
    if(depth == 0)
    {
        /* If depth is 0, its the server's certifcate. Print the SANs */
        pkp_print_san_name("Subject (san)", cert, /*sname,*/ NID_subject_alt_name);
    }
    
    if(preverify == 0)
    {
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if(err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if(err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if(err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if(err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if(err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }
    
    /***************************************************************************/
    /* We really don't care what DNS and CAs have to say here. We are going to */
    /* pin the public key after customary SSL/TLS validations. As far as we    */
    /* are concerned, DNS and CAs are untrusted input whose sole purpose in    */
    /* life is to make us fail in spectacular ways.                            */
    /***************************************************************************/
    
    /* If we return 1, then we base all security decisions on the public key  */
    /* of the host. The decision is made above with pkp_pin_peer_pubkey()     */
    /* return 1; */
    
    /* Or, we can return the result of `preverify`, which is the result of    */
    /* customary X509 verifcation. We should still make our final security    */
    /* decision based upon pkp_pin_peer_pubkey().                             */
    return preverify;
}

BoostAsioSslClient::BoostAsioSslClient(
        boost::asio::io_context & io_context,
        boost::asio::ssl::context & sslCtx,
        const std::string & myCertFile,
        const std::string & myPrivateKeyFile,
        const std::string & caCertFile,
        const std::string & hostname,
        const int port ) : 
    remotePort_(port),
    caCertFile_(caCertFile),
    remoteHost_(hostname),
    localCertFile_(myCertFile),
    localPrivateKeyFile_(myPrivateKeyFile),
    sslCtx_(boost::asio::ssl::context::tls),
    resolver_(io_context),
    socket_(io_context, sslCtx)
{
    sslCtx_.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1 |
            boost::asio::ssl::context::no_tlsv1_2 );
          //  boost::asio::ssl::context::single_dh_use |
 
    sslCtx_.set_verify_mode(
		    boost::asio::ssl::verify_peer |
		    boost::asio::ssl::verify_fail_if_no_peer_cert);

    //
    // https://www.boost.org/doc/libs/1_81_0/boost/asio/ssl/host_name_verification.hpp
    //
    // Boost host_name_verification verifies a certificate against a host_name
    // according to the rules described in RFC 6125.
    //
    socket_.set_verify_callback(
		    make_verbose_verification(
			    boost::asio::ssl::host_name_verification(remoteHost_)));
			    // boost::asio::ssl::rfc2818_verification(remoteHost_)));
           //std::bind(&BoostAsioSslClient::verify_certificate, this, _1, _2));

    sslCtx_.load_verify_file(caCertFile_.c_str());
    // sslCtx_.use_certificate_file(localCertFile_.c_str(), boost::asio::ssl::context::pem);
    sslCtx_.use_certificate_chain_file(localCertFile_.c_str());
    sslCtx_.use_private_key_file(localPrivateKeyFile_.c_str(), boost::asio::ssl::context::pem);
    endpoints_ = resolver_.resolve(remoteHost_, std::to_string(remotePort_));
    connect(endpoints_);
}

bool BoostAsioSslClient::verify_certificate(
        bool preverified,
        boost::asio::ssl::verify_context& ctx)
{
    // The verify callback can be used to check whether the certificate that is
    // being presented is valid for the peer. For example, RFC 2818 describes
    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    // documentation for more details. Note that the callback is called once
    // for each certificate in the certificate chain, starting from the root
    // certificate authority.

    // In this example we will simply print the certificate's subject name.
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    std::cout << "Verifying " << subject_name << "\n";

    return preverified;
}

void BoostAsioSslClient::connect(const tcp::resolver::results_type& endpoints)
{
    boost::asio::async_connect(socket_.lowest_layer(), endpoints,
            [this](const boost::system::error_code& error,
                const tcp::endpoint& /*endpoint*/)
            {
            if (!error)
            {
            handshake();
            }
            else
            {
            std::cout << "Connect failed: " << error.message() << "\n";
            }
            });
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
void BoostAsioSslClient::checkPinnedPublicKey( void )
{
    FILE* fp = NULL;

    unsigned char *buff1 = NULL;
    unsigned char *buff2 = NULL;
    
    int ret = 0;
    bool result = false;

    /* http://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html */
    X509 * cert = SSL_get_peer_certificate(socket_.native_handle());
    long ssl_err = ERR_get_error();

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


    



    if( pubKeyBuffer != NULL ) OPENSSL_free(pubKeyBuffer);

    do
    {


        
        
        /* Begin Gyrations to get the subjectPublicKeyInfo       */
        /* Thanks to Viktor Dukhovni on the OpenSSL mailing list */
        /* http://groups.google.com/group/mailing.openssl.users/browse_thread/thread/d61858dae102c6c7 */
        int len1 = i2d_X509_PUBKEY( X509_get_X509_PUBKEY(cert), NULL );
        ssl_err = (long)ERR_get_error();
        
        if( len1 <= 0 )
        {
            pkp_display_error("i2d_X509_PUBKEY (1)", ssl_err);
            break; /* failed */
        }
        
        /* scratch */
        unsigned char* temp = NULL;
        
        /* http://www.openssl.org/docs/crypto/buffer.html */
        buff1 = temp = (unsigned char*)OPENSSL_malloc(len1);
        ssl_err = (long)ERR_get_error();
        
        if( NULL == buff1 )
        {
            pkp_display_error("OpenSSL_malloc (1)", ssl_err);
            break; /* failed */
        }
        
        /* http://www.openssl.org/docs/crypto/d2i_X509.html */
        int len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp);
        ssl_err = (long)ERR_get_error();
        
        /* These checks are making sure we got back the same values as when we sized the buffer.    */
        /* Its pretty weak since they should always be the same. But it gives us something to test. */

        if( len1 != len2 )
        {
            pkp_display_error("i2d_X509_PUBKEY: (len1 != len2)", ssl_err);
            break; /* failed */
        }

        if( NULL == temp )
        {
            pkp_display_error("i2d_X509_PUBKEY: (NULL == temp)", ssl_err);
            break; /* failed */
        }

        if( (temp - buff1) != len1 )
        {
            pkp_display_error("i2d_X509_PUBKEY ((temp - buff1) != len1)", ssl_err);
            break;
        }

        /* End Gyrations */
        
        /* We are getting ready to read (and possibly write) files. Be careful of fopen() and friends. */
        /* fopen_s() is not Posix; and "wx" and "rx" modes are C1X, and not generally available.       */
        /* You might find it best to use open(..., O_EXCL | O_RDONLY,... ) or                          */
        /*   open(..., O_CREAT | O_EXCL | O_WRONLY,... ) and friends.                                  */
        /* See, for example, http://pubs.opengroup.org/onlinepubs/7908799/xsh/open.html and            */
        /*   https://www.securecoding.cert.org/confluence/display/seccode/FIO03-C                      */
        
        //
        //
        //
        /* Write out the expected public key (useful for boot strapping during first run) */
        BIO* file = BIO_new_file("random-org-xxx.der", "wx");

        if(NULL == file)
            file = BIO_new_file("random-org-xxx.der", "w");
        
        if(NULL != file) 
        {
            ret = BIO_write(file, buff1, len1);
            if(ret != len1)
            {
                pkp_display_error("BIO_write error, ret != len1", ssl_err);
            }
            
            BIO_free_all(file);
        }
        

        /* See the warning above!!!                                            */
        /* http://pubs.opengroup.org/onlinepubs/009696699/functions/fopen.html */
        fp = fopen("random-org.der", "rx");
        ssl_err = errno;
        
        if(NULL ==fp) {
            fp = fopen("random-org.der", "r");
            ssl_err = errno;
        }
        
        if(!(NULL != fp))
        {
            pkp_display_error("fopen", ssl_err);
            break; /* failed */
        }
        
        /* Seek to eof to determine the file's size                            */
        /* http://pubs.opengroup.org/onlinepubs/009696699/functions/fseek.html */
        ret = fseek(fp, 0, SEEK_END);
        ssl_err = errno;
        
        if(!(0 == ret))
        {
            pkp_display_error("fseek (1)", ssl_err);
            break; /* failed */
        }
        
        /* Fetch the file's size                                               */
        /* http://pubs.opengroup.org/onlinepubs/009696699/functions/ftell.html */
        long size = ftell(fp);
        ssl_err = errno;
        
        /* Arbitrary size, but should be relatively small (less than 1K or 2K) */
        if(!(size != -1 && size > 0 && size < 2048))
        {
            pkp_display_error("ftell", ssl_err);
            break; /* failed */
        }
        
        /* Rewind to beginning to perform the read                             */
        /* http://pubs.opengroup.org/onlinepubs/009696699/functions/fseek.html */
        ret = fseek(fp, 0, SEEK_SET);
        ssl_err = errno;
        
        if(!(0 == ret))
        {
            pkp_display_error("fseek (2)", ssl_err);
            break; /* failed */
        }
        
        /* Re-use buff2 and len2 */
        buff2 = NULL; len2 = (int)size;
        
        /* http://www.openssl.org/docs/crypto/buffer.html */
        buff2 = (unsigned char*)OPENSSL_malloc(len2);
        ssl_err = (long)ERR_get_error();
        
        if(!(buff2 != NULL))
        {
            pkp_display_error("OpenSSL_malloc (2)", ssl_err);
            break; /* failed */
        }
        
        /* http://pubs.opengroup.org/onlinepubs/009696699/functions/fread.html */
        /* Returns number of elements read, which should be 1 */
        ret = (int)fread(buff2, (size_t)len2, 1, fp);
        ssl_err = errno;
        
        if(!(ret == 1))
        {
            pkp_display_error("fread", ssl_err);
            break; /* failed */
        }
        
        /* Re-use size. MIN and MAX macro below... */
        size = len1 < len2 ? len1 : len2;
        
        /*****************/
        /*    PAYDIRT    */
        /*****************/
        if(len1 != (int)size || len2 != (int)size || 0 != memcmp(buff1, buff2, (size_t)size))
        {
#if 0
            // This was needed on FEB 18 2013. It appears the public key changed a few
            // days earlier. And needed again in NOV 2013. So much for key continuity!
            BIO* file = BIO_new_file("random-org-received.der", "wx");
            if(NULL == file)
                file = BIO_new_file("random-org-received.der", "w");
            
            ASSERT(NULL != file);
            if(NULL != file) {
                ret = BIO_write(file, buff1, len1);
                ASSERT(ret == len1);
                
                BIO_free_all(file);
            }
#endif
            
            pkp_display_error("Public key is not expected", 0);
            break; /* failed */
        }
        
        /* The one good exit point */
        result = true;
        (void)result;
        
        fprintf(stdout, "  success\n");
        
    } while(0);
    
    if(fp != NULL)
        fclose(fp);
    
    /* http://www.openssl.org/docs/crypto/buffer.html */
    if(NULL != buff2)
        OPENSSL_free(buff2);
    
    /* http://www.openssl.org/docs/crypto/buffer.html */
    if(NULL != buff1)
        OPENSSL_free(buff1);
    
    /* http://www.openssl.org/docs/crypto/X509_new.html */
    if(NULL != cert)
        X509_free(cert);
}


void BoostAsioSslClient::handshake( void )
{
    socket_.async_handshake(boost::asio::ssl::stream_base::client,
        [this](const boost::system::error_code& error)
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
                        checkPinnedPublicKey();
                        send_request();
                    }
                    else
                    {
                        std::cerr << "SSL_get_verify_result failed. [" << res << "]  Exiting. "
                            << std::endl;
                    }

                    //if (X509* cert = SSL_get_peer_certificate(socket_.native_handle()))
                    //{
                    //   (void)cert; // for now to get rid of error warning
                    //   if (SSL_get_verify_result(socket_.native_handle()) == X509_V_OK)
                    //   {
                         
                    //   }
                    //}
                }
                else
                {
                    std::cout << "Handshake failed: " << error.message() << "\n";
                }
            });
}

void BoostAsioSslClient::send_request( void )
{
    std::cout << "Enter message: ";
    std::cin.getline(request_, max_length);
    size_t request_length = std::strlen(request_);

    boost::asio::async_write(socket_,
            boost::asio::buffer(request_, request_length),
            [this](const boost::system::error_code& error, std::size_t length)
            {
            if (!error)
            {
            receive_response(length);
            }
            else
            {
            std::cout << "Write failed: " << error.message() << "\n";
            }
            });
}

void BoostAsioSslClient::receive_response(std::size_t length)
{
    boost::asio::async_read(socket_,
            boost::asio::buffer(reply_, length),
            [this](const boost::system::error_code& error, std::size_t length)
            {
            if (!error)
            {
            std::cout << "Reply: ";
            std::cout.write(reply_, length);
            std::cout << "\n";
            }
            else
            {
            std::cout << "Read failed: " << error.message() << "\n";
            }
            });
}


