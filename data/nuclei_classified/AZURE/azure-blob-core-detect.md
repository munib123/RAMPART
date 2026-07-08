# Vulnerability: Azure Blob Core Service - Detect
**Classification:** AZURE
**Source:** Nuclei Template (`azure-blob-core-detect.yaml`)

## Description
This template detects the presence of 'blob.core.windows.net' in the response body, indicating potential references to Azure Blob Storage.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

