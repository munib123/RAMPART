# Vulnerability: Springboot Loggers - Exposure
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-loggers.yaml`)

## Description
Springboot Loggers is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/loggers
GET {{BaseURL}}/actuator/loggers
```

