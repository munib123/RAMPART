# Vulnerability: Apache Tomcat Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`public-tomcat-manager.yaml`)

## Description
Apache Tomcat Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/manager/html
GET {{BaseURL}}/host-manager/html
```

