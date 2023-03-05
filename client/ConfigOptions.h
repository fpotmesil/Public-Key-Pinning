#ifndef CONFIG_OPTIONS_H__
#define CONFIG_OPTIONS_H__

#include <string>

class ConfigOptions
{
    public:
        ConfigOptions( const char * configFilePath );

        const std::string getCertFileName( void ) const
        {
            return certFileName;
        }
            
        const std::string getCaFileName( void ) const
        {
            return caFileName;
        }

    private:
        ConfigOptions( void ) = delete;
        ConfigOptions( const ConfigOptions & options ) = delete;
        ConfigOptions & operator=( const ConfigOptions & options ) = delete;

        std::string configFileName;
        std::string certFileName;
        std::string caFileName;
};



#endif  /* define CONFIG_OPTIONS_H__ */

