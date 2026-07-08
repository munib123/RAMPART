# Vulnerability: Detect Springboot Conditions Actuator
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-conditions.yaml`)

## Description
Springboot Conditions Actuator is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/conditions
GET {{BaseURL}}/actuator/conditions
```

