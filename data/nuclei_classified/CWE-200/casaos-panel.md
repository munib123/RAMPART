# Vulnerability: CasaOS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`casaos-panel.yaml`)

## Description
CasaOS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/#/login
```

