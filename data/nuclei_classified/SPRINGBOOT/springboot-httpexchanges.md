# Vulnerability: Detects Springboot HTTP Exchanges Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-httpexchanges.yaml`)

## Description
The exposed httpexchanges endpoint can leak recent HTTP request/response data, including URIs, headers, and status codes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/httpexchanges
GET {{BaseURL}}/actuator/httpexchanges
```

