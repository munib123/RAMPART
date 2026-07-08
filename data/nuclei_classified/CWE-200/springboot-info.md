# Vulnerability: Spring Boot Information Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`springboot-info.yaml`)

## Description
Spring Boot information panel displaying app name, version information, and other values was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/info
GET {{BaseURL}}/actuator/info
GET {{BaseURL}}/management
GET {{BaseURL}}/management/info
```

