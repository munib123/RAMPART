# Vulnerability: Whisparr Dashboard - Unauthenticated
**Classification:** WHISPARR
**Source:** Nuclei Template (`whisparr-dashboard-unauth.yaml`)

## Description
Exposure of Whisparr dashboard which can lead to sensitive information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

