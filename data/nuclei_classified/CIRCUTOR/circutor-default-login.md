# Vulnerability: Circutor Line-TCPRS1 - Default Login
**Classification:** CIRCUTOR
**Source:** Nuclei Template (`circutor-default-login.yaml`)

## Description
A default login was discovered on a Circutor Line-TCPRS1 device. An attacker can obtain access to user accounts, access sensitive information, modify data, and execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v1/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json;charset=UTF-8

{"Username":"{{username}}","Password":"{{password}}"}
```

