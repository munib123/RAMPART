# Vulnerability: Moleculer Microservices Project
**Classification:** MISCONFIG
**Source:** Nuclei Template (`moleculer-microservices.yaml`)

## Description
Moleculer microservice was able to be accessed with no required authentication in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

