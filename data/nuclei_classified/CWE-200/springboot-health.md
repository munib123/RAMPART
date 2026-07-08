# Vulnerability: Spring Boot Health Actuator Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-health.yaml`)

## Description
Spring Boot Health Actuator panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/health
GET {{BaseURL}}/actuator/health
```

