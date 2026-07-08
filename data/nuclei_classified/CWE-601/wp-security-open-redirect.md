# Vulnerability: WordPress All-in-One Security <=4.4.1 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`wp-security-open-redirect.yaml`)

## Description
WordPress All-in-One Security plugin through 4.4.1 contains an open redirect vulnerability which can expose the actual URL of the hidden login page feature. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Secure Mitigation
Upgrade to 4.4.2 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?aiowpsec_do_log_out=1&after_logout=https://interact.sh
```

