# Vulnerability: Detect Springboot httptrace
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-httptrace.yaml`)

## Description
View recent HTTP requests and responses

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/httptrace
GET {{BaseURL}}/actuator/httptrace
```

