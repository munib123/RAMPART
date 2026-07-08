# Vulnerability: Detect Springboot Mappings Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-mappings.yaml`)

## Description
Additional routes may be displayed

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mappings
GET {{BaseURL}}/actuator/mappings
```

