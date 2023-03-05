#ifndef BOOST_ASIO_SSL_CLIENT_H__
#define BOOST_ASIO_SSL_CLIENT_H__
//
// Started from Boost Example client.cpp
// https://www.boost.org/doc/libs/1_81_0/doc/html/boost_asio/example/cpp11/ssl/client.cpp
//
// Copyright (c) 2003-2022 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <fstream>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

enum { max_length = 1024 };

class BoostAsioSslClient
{
    public:
        BoostAsioSslClient(boost::asio::io_context& io_context,
                boost::asio::ssl::context& context,
                const tcp::resolver::results_type& endpoints);

    private:
        bool verify_certificate(bool preverified,
                boost::asio::ssl::verify_context& ctx);

        void connect(const tcp::resolver::results_type& endpoints);

        void handshake( void );

        void send_request( void );

        void receive_response(std::size_t length);

        boost::asio::ssl::stream<tcp::socket> socket_;
        char request_[max_length];
        char reply_[max_length];
};


#endif  /* #define BOOST_ASIO_SSL_CLIENT_H__*/
