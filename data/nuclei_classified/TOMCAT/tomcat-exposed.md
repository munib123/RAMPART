# Vulnerability: Tomcat Exposed - Detect
**Classification:** TOMCAT
**Source:** Nuclei Template (`tomcat-exposed.yaml`)

## Description
An Apache Tomcat instance was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/host-manager/html
GET {{BaseURL}}/manager/status
GET {{BaseURL}}/manager/html
GET {{BaseURL}}/docs/
GET {{BaseURL}}/examples/
```

