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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using boost::asio::ip::tcp;

#include "BoostAsioSslSession.h"
#include "BoostAsioSslServer.h"

BoostAsioSslServer::BoostAsioSslServer(
        boost::asio::io_context & io_context, 
        const std::string & myCertFile,
        const std::string & myPrivateKeyFile,
        const std::string & caCertFile,
        const int port ) :
    acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
    context_(boost::asio::ssl::context::tls),
    io_context_(io_context), 
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
            boost::asio::ssl::context::no_tlsv1_1 );//|
            //boost::asio::ssl::context::no_tlsv1_2 );

          //  boost::asio::ssl::context::single_dh_use |
          //  SSL_OP_CIPHER_SERVER_PREFERENCE );

    context_.set_verify_mode(
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_client_once |
            boost::asio::ssl::verify_fail_if_no_peer_cert);

    SSL_CTX * ctx = context_.native_handle();
     
    if( NULL != ctx )
    {
        std::cout << "Setting Client CA list from " << caCertFile << std::endl;

        SSL_CTX_set_client_CA_list( ctx, 
                SSL_load_client_CA_file( caCertFile_.c_str() ));
    }
    else
    {
        std::cout << "ERROR getting SSL_CTX from boost native_handle!" << std::endl;
    }

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
    context_.set_verify_depth(4);
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
                std::string tempHost = socket.remote_endpoint().address().to_string();
                int tempPort = socket.remote_endpoint().port();

                std::cout << "The connected socket address is: " << tempHost 
                    << ", and the port is : " << tempPort << std::endl;

                struct sockaddr_in sa;    /* input */
                memset(&sa, 0, sizeof(struct sockaddr_in));

                /* For IPv4*/
                sa.sin_family = AF_INET;
                sa.sin_addr.s_addr = inet_addr(tempHost.c_str());
                socklen_t len = sizeof(struct sockaddr_in);

                char hostnameBuffer[NI_MAXHOST];
                if (getnameinfo((struct sockaddr *) &sa, len, hostnameBuffer, 
                            sizeof(hostnameBuffer), NULL, 0, NI_NAMEREQD)) 
                {
                    std::cout << "could not resolve hostname: " << strerror(errno) << std::endl;
                }
                else 
                {
                    tempHost = hostnameBuffer;
                    std::cout << "The connected hostname is: " << tempHost << std::endl;
                }

                auto session = std::make_shared<BoostAsioSslSession>(
                        std::move(socket), context_, tempHost );
                    //context_, boost::asio::ssl::stream<tcp::socket>(
                    //    std::move(socket), context_) );

                    session->start();
            }

            do_accept();
        });
}



