# Vulnerability: CX Cloud Unauthenticated Upload - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cx-cloud-upload-detect.yaml`)

## Description
CX Cloud unauthenticated upload was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/upload.jsp
```

