#!/bin/bash
help()
{
   # Display Help
   echo "Simple certificate signing script. -f <csr filename> -m <client|server>"
   echo
   echo "Syntax: $0 [-m|h|c]"
   echo "options:"
   echo "-h  Print this Help."
   echo "-m  Certificate Signing Mode - client or server"
   echo "-f  Certificate Signing Request (CSR Filename) to sign"
   echo
}

unset -v csrFileName
unset -v signingMode

while getopts "hm:f:" option; do
   case $option in
      h) # display Help
         help
         exit;;
      f) # Certificate Signing Request Filename
         csrFileName=$OPTARG;;
      m) # Certificate Signing Mode
         signingMode=$OPTARG;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

if [ -z "$csrFileName" ]
then
    echo "Must pass the CSR filename to this script"
    read -p "Enter the CSR file to sign: " csrFileName
fi

if [ -z "$signingMode" ]
then
    echo "Must pass the signing mode to this script"
    read -p "Enter the signing mode to use: client|server: " signingMode
fi

extensions=server_cert
local orig_nocasematch=$(shopt -p nocasematch; true)
shopt -s nocasematch

case "$signingMode" in
 "server" ) extensions=server_cert;;
 "client" ) extensions=client_cert;;
 *) echo "Invalid signing mode, defaulting to server!";;
esac

$orig_nocasematch

echo "CSR file is $csrFileName, mode is $signingMode!"
##filename=$(basename -- "$fullfile")
extension="${filename##*.}"
##filename="${filename%.*}"
filename="${csrFileName%.*}"
echo "CSR filename is $filename, written out as $filename.cert.pem, using extensions $extensions"
outputCertFile="$filename.cert.pem"
read -p "Continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1

echo "Moving $csrFileName to CSR directory: CA/Intermediate/csr"
mv $csrFileName CA/Intermediate/csr 
cd CA
openssl ca -config  Intermediate/cnf/intermediate_ca.cnf -in Intermediate/csr/$csrFileName -out Certificates/$outputCertFile -extensions $extensions
cd ../


