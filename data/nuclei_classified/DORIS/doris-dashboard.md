# Vulnerability: Doris Dashboard - Exposed
**Classification:** DORIS
**Source:** Nuclei Template (`doris-dashboard.yaml`)

## Description
Unauthorized access to the Doris Dashboard.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

