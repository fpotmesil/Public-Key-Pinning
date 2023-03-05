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


