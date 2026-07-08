# Vulnerability: JBoss Web Service Console - Detect
**Classification:** JBOSS
**Source:** Nuclei Template (`jboss-web-service.yaml`)

## Description
The JBoss Web Service console discloses the details of the remote system, The console displays all the web services and exposed by the system leading to a potential information disclosure.

## Secure Mitigation
Restrict access to the ws service

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jbossws/services
```

