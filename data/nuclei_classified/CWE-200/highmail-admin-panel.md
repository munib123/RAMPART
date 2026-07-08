# Vulnerability: HighMail Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`highmail-admin-panel.yaml`)

## Description
HighMail admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

