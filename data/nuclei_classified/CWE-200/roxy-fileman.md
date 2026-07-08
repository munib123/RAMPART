# Vulnerability: Roxy File Manager - Panel Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`roxy-fileman.yaml`)

## Description
Roxy File Manager panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/index.html
GET {{BaseURL}}/fileman/index.html
GET {{BaseURL}}/fileman/php/fileslist.php
GET {{BaseURL}}/fileman/asp_net/main.ashx
```

