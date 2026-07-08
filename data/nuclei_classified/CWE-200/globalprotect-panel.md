# Vulnerability: Palo Alto Networks GlobalProtect Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`globalprotect-panel.yaml`)

## Description
Palo Alto Networks GlobalProtect login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/global-protect/login.esp
GET {{BaseURL}}/sslmgr
```

