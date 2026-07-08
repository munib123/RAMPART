# Vulnerability: Unauthenticated Mercurial Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-mercurial.yaml`)

## Description
Mercurial repositories index is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

