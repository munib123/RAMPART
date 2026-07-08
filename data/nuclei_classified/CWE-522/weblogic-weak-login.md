# Vulnerability: WebLogic Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`weblogic-weak-login.yaml`)

## Description
WebLogic default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /console/ HTTP/1.1
Host: {{Hostname}}

POST /console/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{ username }}&j_password={{ password }}&j_character_encoding=UTF-8
```

