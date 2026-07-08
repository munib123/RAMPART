# Vulnerability: SMTP4Dev Interface - Exposed
**Classification:** SMTP4DEV
**Source:** Nuclei Template (`smtp4dev-interface-exposed.yaml`)

## Description
Publicly exposed smtp4dev interface allowing access to intercepted emails and test configurations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

