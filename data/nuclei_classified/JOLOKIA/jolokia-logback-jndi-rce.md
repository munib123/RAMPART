# Vulnerability: Jolokia Logback JNDI - Remote Code Execution
**Classification:** JOLOKIA
**Source:** Nuclei Template (`jolokia-logback-jndi-rce.yaml`)

## Description
Jolokia Logback is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jolokia/list
GET {{BaseURL}}/actuator/jolokia/list
```

