
#include <boost/program_options.hpp>
namespace po = boost::program_options;


#include <iostream>
#include <fstream>
#include <iterator>

#include "ConfigOptions.h"

ConfigOptions::ConfigOptions( const char * configFilePath ) : configFileName(configFilePath)
{
    std::cout << "Here we are in constructor with config file: " << configFilePath << std::endl;
    readConfigFile();
}

//
// The config file neesd to provide:
// Our Local Certificate.  Could be a 'client' cert or a 'server' cert.
// The CA chain certs
// If this is a client, we need server hostname and port to connect to.
// If this is a server, we need port to listen on.
//
void ConfigOptions::readConfigFile( void )
{
    po::options_description config("Configuration");
    config.add_options()
        ("listen_port", po::value<int>(&listenPort)->default_value(15555), 
         "port to listen and accept connections on if server")

        ("server_port", po::value<int>(&serverPort)->default_value(15555), 
         "server port to connect to if client")

        ("server_hostname", po::value<std::string>(&serverName), 
         "server to connect to if client")

        ("role", po::value<std::string>(&role)->default_value("client"), 
         "computer role in connections, client or server")

        ("local_cert", po::value<std::string>(&certFileName), 
         "local computer certificate filename and path")

        ("hash_data_file", po::value<std::string>(&hashDataFileName), 
         "file containing the hashed SPKI data for allowed connections")

        ("local_cert_private_key", po::value<std::string>(&certPrivateKeyFileName), 
         "local computer certificate private key filename and path")

        ("ca_chain_cert", po::value<std::string>(&caFileName), 
         "certificate authority cert chain filename and path");

    po::variables_map vm;
    std::ifstream fin( configFileName.c_str() );

    if( !fin.good() )
    {
        std::cout << "Error Opening Config File: " 
            << configFileName << ": " << strerror(errno) << std::endl;

        exit(1); // ok for now.  should throw an exception.
    }
    else
    {
        store(parse_config_file(fin, config), vm);
        notify(vm);
        fin.close();
    }

    //
    // FJP TODO - error and validity checks!!
    // client needs server port and hostname
    // server needs listening port.
    // both client and server need certificates and the Root CA chain.
    //
    if( vm.count("role") ) 
    {
        std::cout << "Computer Role set to "
            << vm["role"].as<std::string>() << ".\n";
    }
    else 
    {
        std::cout << "Error: Computer Role was not set!" << std::endl;
        exit(1); // ok for now.  should throw an exception.
    }

    if( vm.count("local_cert") ) 
    {
        std::cout << "Our Local Computer Certificate is " << certFileName << std::endl;
    }
    else 
    {
        std::cout << "Error: Local computer certificate filename was not provided." << std::endl;
        exit(1); // ok for now.  should throw an exception.
    }

    if( vm.count("local_cert_private_key") ) 
    {
        std::cout << "Our Local Computer Certificate Private Key is " 
            << certPrivateKeyFileName << std::endl;
    }
    else 
    {
        std::cout << "Error: Local computer certificate private key filename was not provided." 
            << std::endl;
        exit(1); // ok for now.  should throw an exception.
    }

    if( vm.count("ca_chain_cert") ) 
    {
        std::cout << "Root Certificate Authority Chain Filename is " << caFileName << std::endl;
    }
    else 
    {
        std::cout << "Error: Root certificate authority chain filename was not provided."
            << std::endl;
        exit(1); // ok for now.  should throw an exception.
    }
}


