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
        const unsigned short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
    context_(boost::asio::ssl::context::sslv23)
{
    context_.set_options(
            boost::asio::ssl::context::default_workarounds
            | boost::asio::ssl::context::no_sslv2
            | boost::asio::ssl::context::single_dh_use);

    context_.set_password_callback(std::bind(&BoostAsioSslServer::get_password, this));
    context_.use_certificate_chain_file("server.pem");
    context_.use_private_key_file("server.pem", boost::asio::ssl::context::pem);
    context_.use_tmp_dh_file("dh4096.pem");

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



