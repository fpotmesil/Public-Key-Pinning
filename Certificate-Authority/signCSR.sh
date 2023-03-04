
openssl ca -config  Intermediate/cnf/ -in $inputCSR -out certs/$outputCSR -extensions/server_cert
openssl ca -config  Intermediate/cnf/ -in $inputCSR -out certs/$outputCSR -extensions/client_cert


