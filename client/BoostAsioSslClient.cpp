//
// Started from Boost Example client.cpp
// https://www.boost.org/doc/libs/1_81_0/doc/html/boost_asio/example/cpp11/ssl/client.cpp
//
// Copyright (c) 2003-2022 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


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
    : verifier_(verifier)
  {}

  bool operator()(
    bool preverified,
    boost::asio::ssl::verify_context& ctx )
  {
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
    socket_(io_context, sslCtx_)
{
    socket_.set_verify_mode(
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
    sslCtx_.use_certificate_file(localCertFile_.c_str(), boost::asio::ssl::context::pem);
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

void BoostAsioSslClient::handshake( void )
{
    socket_.async_handshake(boost::asio::ssl::stream_base::client,
            [this](const boost::system::error_code& error)
            {
            if (!error)
            {
            send_request();
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


