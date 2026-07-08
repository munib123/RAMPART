# Vulnerability: Siemens SIMATIC 300 Dashboard - Exposed
**Classification:** SIEMENS
**Source:** Nuclei Template (`simatic-dashboard-exposed.yaml`)

## Description
An unauthenticated exposed web interface for Siemens SIMATIC S7-300 was discovered, potentially allowing access without any login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Portal0000.htm
```

