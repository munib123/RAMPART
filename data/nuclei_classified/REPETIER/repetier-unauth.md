# Vulnerability: Repetier Server Dashboard - Unauthenticated
**Classification:** REPETIER
**Source:** Nuclei Template (`repetier-unauth.yaml`)

## Description
Repetier Server Dashboard has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#!/printer/Prusa_I3/print
```

