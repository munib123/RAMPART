# Vulnerability: CloudFront Insecure Origin SSL Protocols
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudfront-insecure-protocol.yaml`)

## Description
Ensure that your Amazon CloudFront Content Delivery Network (CDN) distributions are not using insecure SSL protocols (i.e. SSLv3) for HTTPS communication between CloudFront edge locations and custom origins.

## Secure Mitigation
Configure your CloudFront distribution to enforce the use of secure SSL/TLS protocols (TLS 1.2 or higher) for all origins and disable support for outdated protocols like SSLv3 and TLS 1.0/1.1.

