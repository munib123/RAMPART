# Vulnerability: Springboot Actuator startup
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-startup.yaml`)

## Description
The startup endpoint provides information about the application’s startup sequence.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/startup
GET {{BaseURL}}/actuator/startup
```

