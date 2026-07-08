# Vulnerability: AWS OpenSearch Login - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aws-opensearch-login.yaml`)

## Description
AWS OpenSearch login page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_dashboards/app/login
```

