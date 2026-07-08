# Vulnerability: Asana API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-asana.yaml`)

## Description
Programmatic access to all data in your asana system

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://app.asana.com/api/1.0/users/me
```

