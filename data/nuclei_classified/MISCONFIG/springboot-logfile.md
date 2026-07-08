# Vulnerability: Detects Springboot Logfile Actuator
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-logfile.yaml`)

## Description
Springboot Logfile Actuator is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/logfile
GET {{BaseURL}}/actuator/logfile
GET {{BaseURL}}/actuators/logfile
```

