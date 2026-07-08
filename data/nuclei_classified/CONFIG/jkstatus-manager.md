# Vulnerability: JK Status Manager - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`jkstatus-manager.yaml`)

## Description
Exposed JKStatus manager which is a web-based tool that allows administrators to monitor and manage the connections between the Apache HTTP Server and the Tomcat application server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/status
GET {{BaseURL}}/jkstatus
GET {{BaseURL}}/jkstatus-auth
GET {{BaseURL}}/jk-status
GET {{BaseURL}}/jkmanager
GET {{BaseURL}}/jkmanager-auth
GET {{BaseURL}}/jdkstatus
```

