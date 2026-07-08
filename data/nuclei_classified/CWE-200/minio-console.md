# Vulnerability: MinIO Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`minio-console.yaml`)

## Description
MinIO Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

