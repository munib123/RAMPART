# Vulnerability: Request Baskets - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`request-baskets-exposure.yaml`)

## Description
Request Baskets is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web
```

