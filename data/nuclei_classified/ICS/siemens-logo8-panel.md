# Vulnerability: Siemens Logo! 8 Web - Panel
**Classification:** ICS
**Source:** Nuclei Template (`siemens-logo8-panel.yaml`)

## Description
Siemens Logo! 8 Web Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/logo_login.shtm?!App-Language=1
```

