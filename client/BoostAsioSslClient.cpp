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

BoostAsioSslClient::BoostAsioSslClient(
        boost::asio::io_context& io_context,
        boost::asio::ssl::context& context,
        const tcp::resolver::results_type& endpoints)
    : socket_(io_context, context)
{
    socket_.set_verify_mode(boost::asio::ssl::verify_peer);
    socket_.set_verify_callback(
            std::bind(&BoostAsioSslClient::verify_certificate, this, _1, _2));

    connect(endpoints);
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


