# Vulnerability: S3CFG Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`s3cfg-config.yaml`)

## Description
S3CFG configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.s3cfg
```

