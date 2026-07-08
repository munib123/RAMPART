# Vulnerability: Spring Boot AuditEvents Actuator Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-auditevents.yaml`)

## Description
Spring Boot Auditevents Actuator panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auditevents
GET {{BaseURL}}/actuator/auditevents
```

