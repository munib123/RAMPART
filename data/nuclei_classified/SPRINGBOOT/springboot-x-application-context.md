# Vulnerability: Spring Boot `X-Application-Context` Header Exposure
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-x-application-context.yaml`)

## Description
Detected the presence of the X-Application-Context header in HTTP responses, which can expose sensitive application context information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

