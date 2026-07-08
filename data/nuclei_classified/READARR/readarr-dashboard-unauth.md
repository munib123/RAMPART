# Vulnerability: Readarr Dashboard - Unauthenticated
**Classification:** READARR
**Source:** Nuclei Template (`readarr-dashboard-unauth.yaml`)

## Description
Exposure of Readarr dashboard which can lead to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

