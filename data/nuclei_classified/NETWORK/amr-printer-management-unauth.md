# Vulnerability: AMR Printer Management Dashboard - Exposure
**Classification:** NETWORK
**Source:** Nuclei Template (`amr-printer-management-unauth.yaml`)

## Description
Unauthorized access to the AMR Printer Management dashboard was possible, potentially exposing sensitive printer configuration and management interfaces without proper authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/amr
```

