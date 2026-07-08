# Vulnerability: AWS Credentials - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aws-credentials.yaml`)

## Description
AWS credentials found via /.aws/credentials endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.aws/credentials
```

