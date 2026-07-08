# Vulnerability: LockSelf Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`lockself-panel.yaml`)

## Description
LockSelf login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/application/index.html
```

