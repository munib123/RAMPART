# Vulnerability: CISCO Expressway Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`cisco-expressway-panel.yaml`)

## Description
CISCO Expressway login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

