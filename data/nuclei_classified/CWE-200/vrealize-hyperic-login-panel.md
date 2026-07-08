# Vulnerability: vRealize Hyperic Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vrealize-hyperic-login-panel.yaml`)

## Description
vRealize Hyperic login panel was detected

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/login
```

