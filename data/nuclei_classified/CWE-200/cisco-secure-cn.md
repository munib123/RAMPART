# Vulnerability: Cisco Secure CN Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-secure-cn.yaml`)

## Description
Cisco Secure CN login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

