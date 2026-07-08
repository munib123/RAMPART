# Vulnerability: Pritunl - Panel
**Classification:** PRITUNL
**Source:** Nuclei Template (`pritunl-panel.yaml`)

## Description
Realtime website and application monitoring tool

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

