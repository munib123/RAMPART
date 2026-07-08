# Vulnerability: Spring Eureka Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`spring-eureka.yaml`)

## Description
Spring Eureka is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

