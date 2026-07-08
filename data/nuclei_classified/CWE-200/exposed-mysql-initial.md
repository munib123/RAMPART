# Vulnerability: mysql.initial Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-mysql-initial.yaml`)

## Description
mysql.initial configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mysql.initial.sql
```

