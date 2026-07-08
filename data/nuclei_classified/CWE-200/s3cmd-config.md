# Vulnerability: S3CMD Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`s3cmd-config.yaml`)

## Description
S3CMD configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/s3cmd.ini
```

