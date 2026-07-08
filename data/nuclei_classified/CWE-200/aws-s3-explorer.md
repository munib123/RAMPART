# Vulnerability: Amazon Web Services S3 Explorer - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aws-s3-explorer.yaml`)

## Description
Amazon Web Services S3 Explorer page was detected. Page contains links to sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

