//
// generate-hash utility
//
// Take a certificate and generate a hash value for the X509_PUBKEY structure.
//
// Check the certificate for an X509v3 Subject Alternative Name field.  If that
// is present, check against the Subject Common Name for a match - we only want
// a single FQDN for the key to go with the hash.
//
// Append the key and hash value to a file, that will be used as our PKP file that
// applications can read in at startup to check against.
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

#include "CertificateHashUtility.h"

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
        std::string certFile = readCommandLineOptions(argc, argv);

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
    std::string certFileName;

    po::options_description cmdline("command line options");
    cmdline.add_options()
        ("help", "produce help message")
        ("certificate,c", po::value<std::string>(&certFileName),
         "Certificate file name to generate hash value and key for.");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, cmdline), vm);
    po::notify(vm);    

    if( vm.count("help") ) 
    {
        std::cout << cmdline << "\n";
        exit(0);
    }

    if( vm.count("certificate") ) 
    {
        std::cout << "Checking Certificate File: " 
            << certFileName << std::endl;
    }
    else 
    {
        std::cout << "Pass the name of a certificate file to hash, use '--certificate <certfile>'"
            << std::endl;
        std::cout << cmdline << "\n";
        exit(0);
    }

    return certFileName;
}

