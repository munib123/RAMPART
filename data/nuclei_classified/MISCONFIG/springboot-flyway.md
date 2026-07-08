# Vulnerability: Springboot Flyway API
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-flyway.yaml`)

## Description
This endpoint to retrieve the migrations

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/flyway
GET {{BaseURL}}/actuator/flyway
```

