# Vulnerability: JBoss JMX Management Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jmx-console.yaml`)

## Description
JBoss JMX Management Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jmx-console/
```

