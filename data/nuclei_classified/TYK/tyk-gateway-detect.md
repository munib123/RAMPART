# Vulnerability: Tyk API Gateway - Detection
**Classification:** TYK
**Source:** Nuclei Template (`tyk-gateway-detect.yaml`)

## Description
Detects if the application uses Tyk API Gateway

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hello
```

