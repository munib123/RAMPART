# Vulnerability: Missing Cookie SameSite Strict
**Classification:** CWE-693
**Source:** Nuclei Template (`missing-cookie-samesite-strict.yaml`)

## Description
Identified cookies that lacked the samesite=strict attribute, which prevented enforcement of restrictions on cross-domain cookie transmission.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

