# Vulnerability: CloudFront Security Policy
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudfront-security-policy.yaml`)

## Description
Ensure that your Amazon CloudFront distributions are using a security policy with minimum TLSv1.2 or TLSv1.3 and appropriate security ciphers for HTTPS viewer connections.

## Secure Mitigation
Configure your Amazon CloudFront distributions to use a security policy that enforces a minimum of TLSv1.2 or TLSv1.3 and specifies secure ciphers for HTTPS viewer connections.

