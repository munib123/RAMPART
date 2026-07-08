# Vulnerability: ACM Certificates Pre-expiration Renewal
**Classification:** CLOUD
**Source:** Nuclei Template (`acm-cert-renewal-30days.yaml`)

## Description
Ensure AWS ACM SSL/TLS certificates are renewed at least 30 days before expiration to prevent service disruptions.

## Secure Mitigation
Set up Amazon CloudWatch to monitor ACM certificate expiration and automate renewal notifications or processes.

