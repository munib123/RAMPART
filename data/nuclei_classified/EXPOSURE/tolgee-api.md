# Vulnerability: Tolgee API - Detect
**Classification:** EXPOSURE
**Source:** Nuclei Template (`tolgee-api.yaml`)

## Description
Tolgee API was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/public/configuration
```

