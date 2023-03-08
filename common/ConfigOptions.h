#ifndef CONFIG_OPTIONS_H__
#define CONFIG_OPTIONS_H__

#include <string>

class ConfigOptions
{
    public:
        ConfigOptions( const char * configFilePath );

        const std::string getConfigFileName( void ) const
        {
            return configFileName;
        }

        const std::string getCertFileName( void ) const
        {
            return certFileName;
        }

        const std::string getHashDataFileName( void ) const
        {
            return hashDataFileName;
        }

        const std::string getCertPrivateKeyFileName( void ) const
        {
            return certPrivateKeyFileName;
        }
                    
        const std::string getCaFileName( void ) const
        {
            return caFileName;
        }
     
        const std::string getServerName( void ) const
        {
            return serverName;
        }

        const std::string getRole( void ) const
        {
            return role;
        }

        int getServerPort( void ) const
        {
            return serverPort;
        }

        int getListenPort( void ) const
        {
            return listenPort;
        }

    private:
        ConfigOptions( void ) = delete;
        ConfigOptions( const ConfigOptions & options ) = delete;
        ConfigOptions & operator=( const ConfigOptions & options ) = delete;
        void readConfigFile( void );

        std::string configFileName; // passed into constructor, config file to read.
        std::string certFileName;   // our certificate
        std::string hashDataFileName;   // file for hashed SPKI data of accepted hosts
        std::string certPrivateKeyFileName;     // our private key that goes with our cert
        std::string caFileName;     // CA chain certs
        std::string serverName;     // server name to connect to, if client
        std::string role = "client";           // computer role, client or server
        int serverPort = 0;            // server port to connect to, if client
        int listenPort = 0;            // port to listen and accept connections on, if server
};

#endif  /* define CONFIG_OPTIONS_H__ */

