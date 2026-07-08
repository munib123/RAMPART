# Vulnerability: Insecure SSL Cipher Suites in GCP Load Balancers
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-ssl-policy-insecure-ciphers.yaml`)

## Description
This check scans SSL policies of Google Cloud HTTPS and SSL Proxy load balancers to identify insecure cipher suites. It ensures SSL policies use TLS 1.2 with secure profiles and exclude weak ciphers.

## Secure Mitigation
Ensure SSL policies use MODERN or RESTRICTED profiles, or a secure CUSTOM profile without weak ciphers.

