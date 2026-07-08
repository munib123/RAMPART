# Vulnerability: ZyXel Router Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zyxel-router-panel.yaml`)

## Description
ZyXel Router login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

