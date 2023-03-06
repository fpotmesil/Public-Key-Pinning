//
// server.cpp
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

using boost::asio::ip::tcp;

#include "BoostAsioSslSession.h"
#include "BoostAsioSslServer.h"

BoostAsioSslServer::BoostAsioSslServer(
        boost::asio::io_context& io_context, 
        const std::string & myCertFile,
        const std::string & myPrivateKeyFile,
        const std::string & caCertFile,
        const int port ) :
    acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
    context_(boost::asio::ssl::context::tls),
    listenPort_(port),
    caCertFile_(caCertFile),
    localCertFile_(myCertFile),
    localPrivateKeyFile_(myPrivateKeyFile)
{
    context_.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1 |
            // boost::asio::ssl::context::no_tlsv1_2 |
            boost::asio::ssl::context::single_dh_use |
            SSL_OP_CIPHER_SERVER_PREFERENCE );

    context_.set_verify_mode(
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_fail_if_no_peer_cert);

    //
    // https://www.boost.org/doc/libs/1_81_0/boost/asio/ssl/host_name_verification.hpp
    //
    // Boost host_name_verification verifies a certificate against a host_name
    // according to the rules described in RFC 6125.
    //
    // socket_.set_verify_callback(
    //        make_verbose_verification(
    //            boost::asio::ssl::host_name_verification(
    //                remoteEndpoint_.address().to_string())));

    context_.load_verify_file(caCertFile_.c_str());
    context_.use_certificate_file(localCertFile_.c_str(), boost::asio::ssl::context::pem);
    context_.use_private_key_file(localPrivateKeyFile_.c_str(), boost::asio::ssl::context::pem);

    // context_.set_password_callback(std::bind(&BoostAsioSslServer::get_password, this));
    // context_.use_certificate_chain_file("server.pem");
    // context_.use_private_key_file("server.pem", boost::asio::ssl::context::pem);
    // context_.use_tmp_dh_file("dh4096.pem");

    do_accept();
}

void BoostAsioSslServer::do_accept( void )
{
    acceptor_.async_accept(
        [this](const boost::system::error_code& error, tcp::socket socket)
        {
            if (!error)
            {
                std::make_shared<BoostAsioSslSession>(
                    boost::asio::ssl::stream<tcp::socket>(
                        std::move(socket), context_))->start();
            }

            do_accept();
        });
}



