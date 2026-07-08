# Vulnerability: Scalar API Documentation - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`scalar-detection.yaml`)

## Description
Scalar API documentation panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/scalar
GET {{BaseURL}}
```

