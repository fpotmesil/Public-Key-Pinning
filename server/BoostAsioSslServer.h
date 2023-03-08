#ifndef BOOST_ASIO_SSL_SERVER_H__
#define BOOST_ASIO_SSL_SERVER_H__
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


class BoostAsioSslServer
{
public:
  BoostAsioSslServer(
          boost::asio::io_context& io_context, 
          const std::string & myCertFile,
          const std::string & myPrivateKeyFile,
          const std::string & hashDataFile,
          const std::string & caCertFile,
          const int port );

private:
  std::string get_password() const
  {
    return "test";
  }

  void do_accept( void );

  tcp::acceptor acceptor_;
  boost::asio::ssl::context context_;
  boost::asio::io_context & io_context_;
  const int listenPort_;
  const std::string caCertFile_;
  const std::string remoteHost_;
  const std::string localCertFile_;
  const std::string localPrivateKeyFile_;
  const std::string hashDataFile_;

};

#endif  /* #define BOOST_ASIO_SSL_SERVER_H__ */

