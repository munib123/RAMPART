# Vulnerability: Cisco Prime Infrastructure Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cisco-prime-infrastructure.yaml`)

## Description
A Cisco Prime Infrastructure login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webacs/pages/common/login.jsp
```

