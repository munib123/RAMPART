# Vulnerability: CtrlPanel Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ctrlpanel-panel.yaml`)

## Description
CtrlPanel login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

