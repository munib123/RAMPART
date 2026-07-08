# Vulnerability: MinIO Browser Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`minio-browser.yaml`)

## Description
MinIO Browser login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/minio/login
```

