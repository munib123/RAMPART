# Vulnerability: Seafile API - Detect
**Classification:** EXPOSURE
**Source:** Nuclei Template (`seafile-api.yaml`)

## Description
Seafile API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api2/server-info/
```

