# Vulnerability: Wildcard ACM Certificate Usage
**Classification:** CLOUD
**Source:** Nuclei Template (`acm-wildcard-cert.yaml`)

## Description
Ensure ACM certificates for specific domain names are used over wildcard certificates to adhere to best security practices, providing unique private keys for each domain/subdomain.

## Secure Mitigation
Replace wildcard ACM certificates with single domain name certificates for each domain/subdomain within your AWS account. This enhances security by ensuring each domain/subdomain has its own unique private key and certificate.

