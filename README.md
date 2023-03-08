# Public-Key-Pinning
Demo files for public key pinning in a native application ecosystem


Certificate and Public Key Pinning
Introduction and Applications

X.509v3 SAN: You can trust me, my certs are signed

Providing absolute trust for a certification authority's issued certificates has led to notable security breaches.  
Comodo - around March 2011
https://en.wikipedia.org/wiki/Comodo_Cybersecurity

DigiNotar - detected a breach in July 2011, and failed to report the intrusion.
https://en.wikipedia.org/wiki/DigiNotar
https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/
In July 2011 wildcards certs for Google services, were noticed and published online.

So how did this happen?  Access was gained through a web server.
    Notable:
        1) DigiNotar did have some websites defaced in 2009 - old vulnerabilities?
        2) DigiNotar was sold in Jan 2011 - opened some holes?
        3) Certificate Pinning was being used in Chrome at that time.
            - Iran was sanctioned and they did not have?

Let's discuss certificate pinning.


What is pinning?
forcing a host to associated with a digital identity in the form of an X509 cert or SPKI.

When did it start?  Google Chrome started using pinning in 2011.  SSH clients have effectively pinned public keys for years before that, based on TOFU.     

After the DigiNotar incident

What are some of the issues encountered when only allowing one certificate or public key for a given site?
 Have to control the ecosystem.  Google can do it with Chrome, force updates.
 Android and iPhone applications use pinning a lot.

In addition, I will briefly cover the evolution of certificate pinning in HTTP


Enter Public Key Pinning Extension for HTTP
https://datatracker.ietf.org/doc/html/rfc7469
Around April 2015
Browsers quickly deprecated and removed due to issues 

Now Introducing Certificate Transparency. 
- SCT is generated when a new certificate is submitted to a CT log
- X.509v3 extension embeds the SCT in the cert
- public logs allow for quick detection of incorrectly issued certificates
- must monitor the logs

Sample applications using pinned SPKI data for two way authentication.
Everything available on github:  https://github.com/fpotmesil/Public-Key-Pinning

Application Ecosystem:
- client/server architecture.  Expected to have several clients connected to one single server.
- two way TLS certificate negotiation in place so client and server are both authenticated.
- Client and server certificates use X.509v3 extensions keyUsage, extendedKeyUsage, and nsCertType

More environment notes:
big snappy linux server is the Root and Intermediate CA: snapperhead.loesshillsfarms.org
Pi B+ v1.2 is client #1, hostname curie.loesshillsfarms.org at 192.168.0.60/24
Pi B+ v1.2 is client #2, hostname euclid.loesshillsfarms.org at 192.168.0.61/24
Pi 2 B v1.1 is client #3, hostname newton.loesshillsfarms.org at 192.168.0.62
Pi 4 B is the server, hostname galileo.loesshillsfarms.org at 192.168.0.70





OpenSSL test commands to check for two way TLS handshake:
[fred@snapperhead Public-Key-Pinning]$ openssl s_server -cert snapperhead.loesshillsfarms.org.cert.pem -key ecc.key -port 12345 -CAfile ca-chain-crl.cert.pem -verify_return_error -Verify 1

fred@curie:~/Public-Key-Pinning/client $ openssl s_client -cert curie.loesshillsfarms.org.cert.pem  -key ecc.key  -CAfile ca-chain-crl.cert.pem -connect snapperhead:12345 -msg -debug

OpenSSL command to pull out SPKI from a certificate and get a hash of the der format in base64.
openssl x509 -in my-certificate.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
