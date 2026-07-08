# Vulnerability: JBoss Management Console Server Information Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jboss-status.yaml`)

## Description
JBoss Management Console server information page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web-console/ServerInfo.jsp
```

