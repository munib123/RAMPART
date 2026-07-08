# Vulnerability: Spring Boot Scheduledtasks Actuator Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-scheduledtasks.yaml`)

## Description
Spring Boot Scheduledtasks Actuator panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/scheduledtasks
GET {{BaseURL}}/actuator/scheduledtasks
```

