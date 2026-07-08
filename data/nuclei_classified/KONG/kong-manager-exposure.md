# Vulnerability: Kong Manager OSS/Admin - Exposure
**Classification:** KONG
**Source:** Nuclei Template (`kong-manager-exposure.yaml`)

## Description
Exposed Kong Manager (OSS/Admin) interface accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

