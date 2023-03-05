
#include <boost/program_options.hpp>
namespace po = boost::program_options;


#include <iostream>
#include <fstream>
#include <iterator>

#include "ConfigOptions.h"

ConfigOptions::ConfigOptions( const char * configFilePath )
{
    std::cout << "Here we are in constructor with config file: " << configFilePath << std::endl;
}

