# Vulnerability: Spring Boot LoggerConfig Actuator Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-loggerconfig.yaml`)

## Description
Spring Boot LoggerConfig Actuator panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/loggingConfig
GET {{BaseURL}}/actuator/loggingConfig
```

