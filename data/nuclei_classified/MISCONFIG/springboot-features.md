# Vulnerability: Detects Springboot Features Actuator
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-features.yaml`)

## Description
Springboot Features Actuator is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/features
GET {{BaseURL}}/actuator/features
```

