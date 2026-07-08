# Vulnerability: Springboot Actuator Caches
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-caches.yaml`)

## Description
The caches endpoint provides access to the application's caches.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/caches
GET {{BaseURL}}/actuator/caches
```

