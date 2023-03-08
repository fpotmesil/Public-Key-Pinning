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
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "BoostAsioSslClient.h"
#include "ConfigOptions.h"

template<class T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& v)
{
    std::copy(v.begin(), v.end(), std::ostream_iterator<T>(os, " ")); 
    return os;
}

std::string readCommandLineOptions(
        const int argc,
        const char * argv[] );

//
// ok how do I want it to start? 
// well.  Good question.  Just "./client <config file name>" would be nice.
// let all the other options be in the config file.
// There should be a default config, and if it does not exist, terimate with an error message.
// If the config file does not have good entries, terminate with an error message.
//
//
int main(const int argc, const char* argv[])
{
    try
    {
        std::string configFile = readCommandLineOptions(argc, argv);
        ConfigOptions config( configFile.c_str() );
        boost::asio::io_context io_context;

        boost::asio::ssl::context sslCtx(boost::asio::ssl::context::tls);
    sslCtx.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1 |
            boost::asio::ssl::context::no_tlsv1_2 );
          //  boost::asio::ssl::context::single_dh_use |
 
    sslCtx.set_verify_mode(
		    boost::asio::ssl::verify_peer |
		    boost::asio::ssl::verify_fail_if_no_peer_cert);
    sslCtx.load_verify_file(config.getCaFileName().c_str());
    // sslCtx_.use_certificate_file(localCertFile_.c_str(), boost::asio::ssl::context::pem);
    sslCtx.use_certificate_chain_file(config.getCertFileName().c_str());
    sslCtx.use_private_key_file(config.getCertPrivateKeyFileName().c_str(), boost::asio::ssl::context::pem);
 
        BoostAsioSslClient client(
                io_context, 
                sslCtx,
                config.getCertFileName(),
                config.getCertPrivateKeyFileName(),
                config.getHashDataFileName(),
                config.getCaFileName(),
                config.getServerName(),
                config.getServerPort() );

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

