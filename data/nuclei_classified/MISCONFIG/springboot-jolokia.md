# Vulnerability: Detects Springboot Jolokia Actuator
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-jolokia.yaml`)

## Description
Springboot Jolokia Actuator is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia
GET {{BaseURL}}/actuator/jolokia
```

