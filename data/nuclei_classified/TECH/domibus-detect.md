# Vulnerability: Domibus - Detect
**Classification:** TECH
**Source:** Nuclei Template (`domibus-detect.yaml`)

## Description
Domibus was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/domibus/rest/application/info
GET {{BaseURL}}/domibus/
```

