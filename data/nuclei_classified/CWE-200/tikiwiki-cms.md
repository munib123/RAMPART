# Vulnerability: Tiki Wiki CMS Groupware Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tikiwiki-cms.yaml`)

## Description
Tiki Wiki CMS Groupware login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tiki-login_scr.php
GET {{BaseURL}}/tiki-login.php
```

