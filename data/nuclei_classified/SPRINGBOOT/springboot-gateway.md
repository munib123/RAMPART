# Vulnerability: Detect Spring Gateway Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-gateway.yaml`)

## Description
Sensitive environment variables may not be masked

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gateway/routes
GET {{BaseURL}}/actuator/gateway/routes
```

