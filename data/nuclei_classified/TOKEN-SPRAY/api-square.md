# Vulnerability: Square API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-square.yaml`)

## Description
Easy way to take payments, manage refunds, and help customers checkout online

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://connect.squareup.com/v2/locations
GET https://connect.squareupsandbox.com/v2/locations
```

