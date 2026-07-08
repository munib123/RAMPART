# Vulnerability: librechat - Config Exposure
**Classification:** LIBRECHAT
**Source:** Nuclei Template (`librechat-config-exposure.yaml`)

## Description
Detected the `/api/config` endpoint of the LibreChat web application was publicly accessible, potentially exposing internal configuration details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/config
```

