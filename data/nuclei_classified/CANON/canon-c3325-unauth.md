# Vulnerability: Canon R-ADV C3325 - Unauth
**Classification:** CANON
**Source:** Nuclei Template (`canon-c3325-unauth.yaml`)

## Description
Canon R-ADV C3325 unauthenticated dashboard has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

