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

BoostAsioSslSession::BoostAsioSslSession(
        boost::asio::ssl::stream<tcp::socket> socket ) :
    socket_( std::move(socket) ),
    remoteEndpoint_(socket_.lowest_layer().remote_endpoint())
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
                boost::asio::ssl::host_name_verification(
                    remoteEndpoint_.address().to_string())));
    //
    // boost::asio::ssl::rfc2818_verification(
    //      remoteEndpoint_.address().to_string()Host_)));
    //
    //std::bind(&BoostAsioSslSession::verify_certificate, this, _1, _2));
}


void BoostAsioSslSession::do_handshake( void )
{
    auto self(shared_from_this());
    socket_.async_handshake(boost::asio::ssl::stream_base::server, 
            [this, self](const boost::system::error_code& error)
            {
            if (!error)
            {
            do_read();
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


