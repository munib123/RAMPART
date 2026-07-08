# Vulnerability: Revoked SSL Certificate - Detect
**Classification:** SSL
**Source:** Nuclei Template (`revoked-ssl-certificate.yaml`)

## Description
Certificate revocation is the act of invalidating a TLS/SSL before its scheduled expiration date. A certificate should be revoked immediately when its private key shows signs of being compromised. It should also be revoked when the domain for which it was issued is no longer operational.

