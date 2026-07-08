# Vulnerability: Tomcat Cookie Exposed
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tomcat-cookie-exposed.yaml`)

## Description
Tomcat Cookie is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/examples/servlets/servlet/CookieExample
```

