# Vulnerability: EWM Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ewm-manager-panel.yaml`)

## Description
EWM Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wfc/
```

