#ifndef BOOST_ASIO_SSL_SESSION_H__
#define BOOST_ASIO_SSL_SESSION_H__
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

using boost::asio::ip::tcp;

class BoostAsioSslSession : public std::enable_shared_from_this<BoostAsioSslSession>
{
    public:
        BoostAsioSslSession(
                boost::asio::ssl::stream<tcp::socket> socket );

        void start( void )
        {
            do_handshake();
        }

    private:
        void do_handshake( void );
        void do_read( void );
        void do_write(std::size_t length);

        boost::asio::ssl::stream<tcp::socket> socket_;
        const boost::asio::ip::tcp::endpoint remoteEndpoint_;
        char data_[1024];
};


#endif  /* #define BOOST_ASIO_SSL_SESSION_H__ */
