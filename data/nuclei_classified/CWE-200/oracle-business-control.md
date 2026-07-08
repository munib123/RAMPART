# Vulnerability: Oracle Commerce Business Control Center Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-business-control.yaml`)

## Description
Oracle Commerce Business Control Center login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/atg/bcc
GET {{BaseURL}}/atg/user/html/login.jsp
```

