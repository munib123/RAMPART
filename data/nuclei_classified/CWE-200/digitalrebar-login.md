# Vulnerability: RackN Digital Rebar Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`digitalrebar-login.yaml`)

## Description
RackN Digital Rebar login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ui
```

