# Vulnerability: Fortinet FortiMail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortimail-panel.yaml`)

## Description
Fortinet FortiMail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/m/
```

