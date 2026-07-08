# Vulnerability: AWS Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aws-config.yaml`)

## Description
AWS config found via /.aws/config.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.aws/config
```

