# Vulnerability: Cisco Integrated Management Controller Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-integrated-login.yaml`)

## Description
Cisco Integrated Management Controller login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

