# Vulnerability: Busybox Repository Browser - Detect
**Classification:** DETECT
**Source:** Nuclei Template (`busybox-repository-browser.yaml`)

## Description
Busybox Repository Browser was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

