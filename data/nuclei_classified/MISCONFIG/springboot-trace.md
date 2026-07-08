# Vulnerability: Detect Springboot Trace Actuator
**Classification:** MISCONFIG
**Source:** Nuclei Template (`springboot-trace.yaml`)

## Description
View recent HTTP requests and responses

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/trace
```

