# Vulnerability: AWS Service - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aws-detect.yaml`)

## Description
Detect if AWS is being used in the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

