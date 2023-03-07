
openssl ecparam -genkey -name secp521r1 -out ecc.key
HostName=$(hostname -f)
DomainName=$(domainname)

#if [ "$DomainName" != "(none)" ]; then
#    echo "Domain Name is $DomainName"
#    v3ExtText="subjectAltName = DNS:$HostName,  DNS:$HostName.$DomainName, DNS:*.$HostName, DNS:*.$HostName.$DomainName"
#    certName="$HostName.$DomainName.csr"
#else
#    echo "Domain name is not set!"
#    v3ExtText="subjectAltName = DNS:$HostName,  DNS:*.$HostName"
#    certName="$HostName.csr"
#fi

if [ "$DomainName" != "(none)" ]; then
    echo "Domain Name is $DomainName"
    v3ExtText="subjectAltName = DNS:$HostName.$DomainName"
    certName="$HostName.$DomainName.csr"
    extFileName="$HostName.$DomainName.ext"
else
    echo "Domain name is not set!"
    v3ExtText="subjectAltName = DNS:$HostName"
    certName="$HostName.csr"
    extFileName="$HostName.ext"
fi

read -p "Enter the signing mode to use: client|server: " signingMode

extensions=server_cert
local orig_nocasematch=$(shopt -p nocasematch; true)
shopt -s nocasematch

case "$signingMode" in
 "server" ) extensions=server_cert;;
 "client" ) extensions=client_cert;;
 *) echo "Invalid signing mode, defaulting to server!";;
esac

if [ "$extensions" = "server_cert" ];
then
cat << EOF > "$extFileName"
$v3ExtText
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
else
cat << EOF > "$extFileName"
$v3ExtText
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
EOF
fi

echo "Adding X509v3 certificate extensions: $v3ExtText"

openssl req -new -key ecc.key -addext "$v3ExtText" -out "$certName"
openssl req -text -in "$certName" -noout




