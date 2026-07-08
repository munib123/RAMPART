# Vulnerability: WordPress All-in-One Security <=4.4.1 - Hidden Login Page Exposure
**Classification:** WP-PLUGIN
**Source:** Nuclei Template (`wp-security-hidden-login-exposure.yaml`)

## Description
WordPress All-in-One Security plugin through 4.4.1 contains an exposure of the actual URL of the "hidden login page" feature.

## Secure Mitigation
Upgrade to 4.4.2 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?aiowpsec_do_log_out=1&al_additional_data=1
```

