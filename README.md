# Public-Key-Pinning
Demo files for public key pinning in a native application ecosystem

OpenSSL test commands to check for two way TLS handshake:
[fred@snapperhead Public-Key-Pinning]$ openssl s_server -cert snapperhead.loesshillsfarms.org.cert.pem -key ecc.key -port 12345 -CAfile ca-chain-crl.cert.pem -verify_return_error -Verify 1

fred@curie:~/Public-Key-Pinning/client $ openssl s_client -cert curie.loesshillsfarms.org.cert.pem  -key ecc.key  -CAfile ca-chain-crl.cert.pem -connect snapperhead:12345 -msg -debug

OpenSSL command to pull out SPKI from a certificate and get a hash of the der format in base64.
openssl x509 -in my-certificate.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
