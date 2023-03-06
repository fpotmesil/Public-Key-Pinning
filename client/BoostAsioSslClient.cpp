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


