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

#include <fstream>
#include <iterator>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <vector>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "BoostAsioSslServer.h"
#include "ConfigOptions.h"

std::string readCommandLineOptions(
        const int argc,
        const char * argv[] );

int main(
        const int argc, 
        const char* argv[] )
{
  try
  {
      std::string configFile = readCommandLineOptions(argc, argv);
      ConfigOptions config( configFile.c_str() );

      //
      // FJP DEBUG
      //
          std::cerr << "Fred is still developing!!: client <host> <port>\n";
          return 1;

    if (argc != 2)
    {
      std::cerr << "Usage: server <port>\n";
      return 1;
    }

    boost::asio::io_context io_context;
    BoostAsioSslServer s(io_context, atoi(argv[1]));
    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}


std::string readCommandLineOptions(
        const int argc,
        const char * argv[] )
{
    const auto host_name = boost::asio::ip::host_name();
    std::string cfgFileName = host_name;
    cfgFileName.append(".cfg");
    std::cout << "Default config file name: " << cfgFileName << std::endl;
    std::string config_file;

    po::options_description cmdline("command line options");
    cmdline.add_options()
        ("version,v", "print version string")
        ("help", "produce help message")
        ("config,c", po::value<std::string>(&config_file)->default_value(cfgFileName.c_str()),
         "Config File Name to use instead of default 'hostname.cfg' format.");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, cmdline), vm);
    po::notify(vm);    

    if( vm.count("help") ) 
    {
        std::cout << cmdline << "\n";
        exit(0);
    }

    if( vm.count("config") ) 
    {
        cfgFileName = vm["config"].as<std::string>();

        std::cout << "Using Command Line Option Config File: " 
            << cfgFileName << std::endl;
        //  << vm["config"].as<std::string>() << ".\n";

    }
    else 
    {
        std::cout << "Config file not passed, using default.\n";
    }

    return cfgFileName;
}

