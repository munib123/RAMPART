# Vulnerability: Unauthenticated Etherpad
**Classification:** ETHERPAD
**Source:** Nuclei Template (`unauth-etherpad.yaml`)

## Description
Finds Etherpad instances that allow adding new notes without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

