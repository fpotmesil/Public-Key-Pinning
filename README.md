# Public-Key-Pinning
Demo files for public key pinning in a native application ecosystem

OpenSSL test commands to check for two way TLS handshake:
[fred@snapperhead Public-Key-Pinning]$ openssl s_server -cert snapperhead.loesshillsfarms.org.cert.pem -key ecc.key -port 12345 -CAfile ca-chain-crl.cert.pem -verify_return_error -Verify 1

fred@curie:~/Public-Key-Pinning/client $ openssl s_client -cert curie.loesshillsfarms.org.cert.pem  -key ecc.key  -CAfile ca-chain-crl.cert.pem -connect snapperhead:12345 -msg -debug


