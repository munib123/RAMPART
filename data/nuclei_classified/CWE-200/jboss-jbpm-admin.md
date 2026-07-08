# Vulnerability: JBoss jBPM Administration Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jboss-jbpm-admin.yaml`)

## Description
JBoss jBPM Administration Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jbpm-console/app/tasks.jsf
```

