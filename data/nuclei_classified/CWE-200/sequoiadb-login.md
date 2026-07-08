# Vulnerability: SequoiaDB Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sequoiadb-login.yaml`)

## Description
SequoiaDB login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html#/
```

