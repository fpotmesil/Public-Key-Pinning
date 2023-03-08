
#include "CertificateFunctions.h"

void parseCertificateSAN( 
        const X509 * cert,
        std::string & value )
{
    /* Print the SAN field if present */
    pkp_print_san_name("Subject (san)", cert, /*sname,*/ NID_subject_alt_name, value);
}

void parseCertificateIssuerName( 
        const X509 * cert,
        std::string & value )
{
    X509_NAME * iname = X509_get_issuer_name(cert);
    
    /* Issuer is the authority we trust that warrants nothing useful */
    pkp_print_cn_name("Issuer (cn)", iname, NID_commonName, value);
}


void parseCertificateCommonName( 
        const X509 * cert, 
        std::string & value )
{
    X509_NAME * sname = X509_get_subject_name(cert);
    
    /* Subject is who the certificate is issued to by the authority  */
    pkp_print_cn_name("Subject (cn)", sname, NID_commonName, value);
}

void pkp_display_error(const char* msg, long err)
{
    if(err == 0x14090086)
        fprintf(stderr, "Error: %s: SSL3_GET_SERVER_CERTIFICATE: certificate verify failed (%ld, %lx)\n", msg, err, err);
    else if (err == 0)
        fprintf(stderr, "Error: %s\n", msg);
    else if(err < 10)
        fprintf(stderr, "Error: %s: %ld\n", msg, err);
    else
        fprintf(stderr, "Error: %s: %ld (%lx)\n", msg, err, err);
}

void pkp_display_warning(const char* msg, long err)
{
    if(err < 10)
        fprintf(stdout, "Warning: %s: %ld\n", msg, err);
    else
        fprintf(stdout, "Warning: %s: %ld (%lx)\n", msg, err, err);
}

void pkp_print_cn_name(
        const char* label,
        X509_NAME* const name,
        int nid,
        std::string & value )
{
    int idx = -1, success = 0;
    unsigned char *utf8 = NULL;
    
    do
    {
        if(!name) break; /* failed */
        
        idx = X509_NAME_get_index_by_NID(name, nid, -1);
        if(!(idx > -1))  break; /* failed */
        
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if(!entry) break; /* failed */
        
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if(!data) break; /* failed */
        
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if(!utf8 || !(length > 0))  break; /* failed */
        
        fprintf(stdout, "  %s: %s\n", label, utf8);
        value.assign((char*)utf8,length);
        success = 1;
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
    {
        value = "";
        fprintf(stdout, "  %s: <not available>\n", label);
    }
}

void pkp_print_san_name(
        const char * label,
        const X509* const cert, 
        int nid,
        std::string & value )
{
    unsigned char* utf8 = NULL;
    int success = 0;
    
    do
    {
        GENERAL_NAMES* names = NULL;
        
        names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, nid, 0, 0 );
        if(!names) break;
        
        int i = 0, numAN = sk_GENERAL_NAME_num(names);
        if(!numAN) break; /* failed */
        
        for( i = 0; i < numAN; ++i )
        {
            GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
            if(!entry) continue;
            
            if(GEN_DNS == entry->type)
            {
                int len1 = 0, len2 = 0;
                
                len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
                if(utf8) {
                    len2 = (int)strlen((const char*)utf8);
                }
                
                if(len1 != len2) {
                    /* Moxie Marlinspike is in the room .... */
                    fprintf(stderr, "  Strlen and ASN1_STRING size do not match (embedded nul?): %d vs %d\n", len2, len1);
                    
                }
                
                /* If there's a problem with string lengths, then     */
                /* we skip the candidate and move on to the next.     */
                /* Another policy would be to fails since it probably */
                /* indicates the client is under attack.              */
                if(utf8 && len1 && len2 && (len1 == len2)) 
                {
                    fprintf(stdout, "  %s: %s\n", label, utf8);
                    value.assign((char*)utf8,len2);
                    success = 1;
                }
                
                if(utf8) 
                {
                    OPENSSL_free(utf8);
                    utf8 = NULL;
                }
            }
            else
            {
                fprintf(stderr, "  Unknown GENERAL_NAME type: %d\n", entry->type);
            }
        }
        
    } while (0);
    
    if(utf8)
        OPENSSL_free(utf8);
    
    if(!success)
    {
        value = "";
        fprintf(stdout, "  %s: <not available>\n", label);
    }
    
}

bool checkPinnedSpkiMap( 
        const std::string & commonName,
        const std::string & base64PUBKEY,
        const std::map<std::string, std::string> & pinnedHostsMap )
{
    bool rval = false;

    auto search = pinnedHostsMap.find( commonName );

    if( search != pinnedHostsMap.end() )
    {
        //
        // found the common name key.
        // now check the certificate.
        //
        const std::string & hashValue = search->second;

        std::cout << __func__ << ":  Common Name " << commonName 
            << " found in the pinned hosts map." 
            << "  Hashed SPKI Data: " << hashValue << std::endl;
        
        if( !base64PUBKEY.compare(hashValue) )
        {
            std::cout << __func__ << ": hashed SPKI values match!  host is pinned and allowed."
                << std::endl;
            rval = true;
        }
        else
        {
            std::cout << __func__ << ": hashed SPKI values DO NOT MATCH:  "
                << base64PUBKEY << std::endl;
        }
    }
    else
    {
        std::cout << __func__ << ":  Common Name " << commonName 
            << " was NOT found in the pinned hosts map. " << std::endl;
    }

    return rval;
}



