# Vulnerability: Oracle Integrated Lights Out Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-integrated-manager.yaml`)

## Description
Oracle Integrated Lights Out Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/iPages/i_login.asp
```

