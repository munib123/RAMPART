# Vulnerability: Springboot Liquidbase API
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-liquidbase.yaml`)

## Description
This liquibase endpoint provides information about database changes

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/liquibase
GET {{BaseURL}}/actuator/liquibase
```

