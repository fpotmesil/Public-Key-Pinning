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
#include <tuple>
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

std::tuple<std::string,std::string>
    readCommandLineOptions(
        const int argc,
        const char * argv[] );

//
// fun little program to read in an X509 cert in PEM format.
//
// needs quite a lot added, but just need a file written out
// with a key/value pair for now, key being cert common name
// and the value being hashed SPKI info pulled from the cert.
//
int main(const int argc, const char* argv[])
{
    try
    {
        const auto args = readCommandLineOptions(argc, argv);
        CertificateHashUtility hasher(std::get<0>(args));
        //
        // might just be best to make all this just happen without
        // the function calls.
        //
        hasher.generateCertificateHash();
        hasher.parseCertificateCommonName();
        hasher.parseCertificateSAN();
        hasher.writeCertificateHash(std::get<1>(args));
        hasher.cleanup();
    }
    catch (std::exception& e)
    {
        std::cerr << "Caught Exception: " << e.what() << "\n";
    }

    return 0;
}

std::tuple<std::string,std::string>
    readCommandLineOptions(
        const int argc,
        const char * argv[] )
{
    std::string certFileName;
    std::string outFileName;

    po::options_description cmdline("command line options");
    cmdline.add_options()
        ("help", "produce help message")
        ("certificate,c", po::value<std::string>(&certFileName),
         "Certificate file name to generate hash value and key for.")
        ("outfile,o", po::value<std::string>(&outFileName),
         "Output file name to write hash value and key to.");

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
        std::cout << cmdline << "\n";
        exit(0);
    }

    if( vm.count("outfile") ) 
    {
        std::cout << "Writing Certificate SPKI Hash File: " 
            << outFileName << std::endl;
    }
    else 
    {
        std::cout << cmdline << "\n";
        exit(0);
    }

    return {certFileName,outFileName};
}

