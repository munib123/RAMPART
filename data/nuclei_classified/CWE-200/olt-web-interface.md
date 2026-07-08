# Vulnerability: OLT Web Management Interface Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`olt-web-interface.yaml`)

## Description
OLT Web Management Interface login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/action/login.html
```

