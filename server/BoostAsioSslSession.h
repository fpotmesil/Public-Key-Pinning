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
using std::placeholders::_1;
using std::placeholders::_2;
class BoostAsioSslSession : public std::enable_shared_from_this<BoostAsioSslSession>
{
    public:
        BoostAsioSslSession(
            tcp::socket socket,
            boost::asio::ssl::context & ctx,
            const std::string & remoteHostname );

        void start( void )
        {
            do_handshake();
        }

    private:

          bool verify_certificate(bool preverified,
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


        void do_handshake( void );
        void do_read( void );
        void do_write(std::size_t length);

        boost::asio::ssl::stream<tcp::socket> socket_;
        boost::asio::ssl::context & context_;
        const boost::asio::ip::tcp::endpoint remoteEndpoint_;
        const std::string remoteHostname_;
        char data_[1024];
};


#endif  /* #define BOOST_ASIO_SSL_SESSION_H__ */
