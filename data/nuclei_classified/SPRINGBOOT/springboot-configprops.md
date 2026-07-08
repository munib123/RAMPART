# Vulnerability: Detect Springboot Configprops Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-configprops.yaml`)

## Description
Sensitive environment variables may not be masked

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configprops
GET {{BaseURL}}/actuator/configprops
```

