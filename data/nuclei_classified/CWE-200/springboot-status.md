# Vulnerability: Spring Boot Status Actuator Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-status.yaml`)

## Description
Spring Boot Status Actuator panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status
GET {{BaseURL}}/actuator/status
```

