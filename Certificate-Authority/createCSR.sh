
openssl ecparam -genkey -name secp521r1 -out ecc.key
HostName=$(hostname -f)
DomainName=$(domainname)

if [ "$DomainName" != "(none)" ]; then
    echo "Domain Name is $DomainName"
    v3ExtText="subjectAltName = DNS:$HostName,  DNS:$HostName.$DomainName, DNS:*.$HostName, DNS:*.$HostName.$DomainName"
    certName="$HostName.$DomainName.csr"
else
    echo "Domain name is not set!"
    v3ExtText="subjectAltName = DNS:$HostName,  DNS:*.$HostName"
    certName="$HostName.csr"
fi

echo "Adding X509v3 certificate extensions: $v3ExtText"

openssl req -new -key ecc.key -addext "$v3ExtText" -out "$certName"
openssl req -text -in "$certName" -noout




