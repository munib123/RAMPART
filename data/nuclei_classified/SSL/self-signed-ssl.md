# Vulnerability: Self Signed SSL Certificate
**Classification:** SSL
**Source:** Nuclei Template (`self-signed-ssl.yaml`)

## Description
self-signed certificates are public key certificates that are not issued by a certificate authority. These self-signed
certificates are easy to make and do not cost money. However, they do not provide any trust value.

## Secure Mitigation
Purchase or generate a proper SSL certificate for this service.

