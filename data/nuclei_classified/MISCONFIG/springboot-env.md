# Vulnerability: Springboot Env Actuator - Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-env.yaml`)

## Description
Sensitive environment variables may not be masked

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/env
GET {{BaseURL}}/actuator/env
GET {{BaseURL}}/actuator;/env;
GET {{BaseURL}}/message-api/actuator/env
```

