#
# https://jamielinux.com/docs/openssl-certificate-authority/index.html
#
echo "Creating CA directory structure"

mkdir CA
cd CA
mkdir Root
cd Root
mkdir certs crl private cnf newcerts
cp ../../root_ca.cnf cnf
:>| index.txt
echo 1000 > serial
cd ../
mkdir Intermediate 
cd Intermediate
mkdir certs crl private cnf csr newcerts
cp ../../intermediate_ca.cnf cnf
:>| index.txt
echo 1000 > serial
echo 1000 > crlnumber
cd ../

echo "Now creating the Root CA private key"
echo "You will be prompted for the root CA private key password"
read -p "Press Enter to Continue..." </dev/tty
openssl genrsa -aes256 -out Root/private/RootCA.key.pem 4096

echo "Now creating the Root CA Certificate"
read -p "Press Enter to Continue..." </dev/tty

openssl req -config Root/cnf/root_ca.cnf -key Root/private/RootCA.key.pem -new \
    -x509 -days 3650 -sha512 -extensions v3_ca -out Root/certs/RootCA.cert.pem

openssl x509 -noout -text -in Root/certs/RootCA.cert.pem
read -p "Press Enter to Continue..." </dev/tty

echo "Now creating the Intermediate CA private key"
echo "You will be prompted for the Intermediate CA private key password"
read -p "Press Enter to Continue..." </dev/tty
openssl genrsa -aes256 -out Intermediate/private/IntermediateCA.key.pem 4096

echo "Creating the Intermediate CSR for the Root CA to sign"
read -p "Press Enter to Continue..." </dev/tty
openssl req -config Intermediate/cnf/intermediate_ca.cnf -new -sha512 \
    -key Intermediate/private/IntermediateCA.key.pem -out Intermediate/csr/Intermediate.csr.pem

openssl ca -config Root/cnf/root_ca.cnf -extensions v3_intermediate_ca -days 365 \
    -md sha512 -in Intermediate/csr/Intermediate.csr.pem \
    -out Intermediate/certs/IntermediateCA.cert.pem

openssl x509 -noout -text -in Intermediate/certs/IntermediateCA.cert.pem
read -p "Press Enter to Continue..." </dev/tty
openssl verify -CAfile Root/certs/RootCA.cert.pem Intermediate/certs/IntermediateCA.cert.pem
read -p "Press Enter to Continue..." </dev/tty
cat Intermediate/certs/IntermediateCA.cert.pem Root/certs/RootCA.cert.pem > \
    Intermediate/certs/ca-chain.cert.pem

openssl ca -config Intermediate/cnf/intermediate_ca.cnf -gencrl -out \
    Intermediate/crl/Intermediate.crl.pem

cat Intermediate/certs/IntermediateCA.cert.pem Intermediate/crl/Intermediate.crl.pem \
    Root/certs/RootCA.cert.pem > Intermediate/certs/ca-chain-crl.cert.pem

mkdir Certificates
cp Intermediate/certs/ca-chain-crl.cert.pem Certificates
cd ../






