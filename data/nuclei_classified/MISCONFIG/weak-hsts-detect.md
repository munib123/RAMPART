# Vulnerability: Weak HTTP Strict-Transport-Security - Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`weak-hsts-detect.yaml`)

## Description
Detected HTTP Strict-Transport-Security header with a weak max-age value (less than one year). A low max-age reduces the effectiveness of HSTS, leaving users vulnerable to protocol downgrade attacks and cookie hijacking during the gap period.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

