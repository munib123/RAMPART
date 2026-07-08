# Vulnerability: AWS Cloudfront service detection
**Classification:** AWS
**Source:** Nuclei Template (`aws-cloudfront-service.yaml`)

## Description
Detect websites using AWS cloudfront service

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

