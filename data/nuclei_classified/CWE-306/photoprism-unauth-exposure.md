# Vulnerability: PhotoPrism - Unauthenticated Exposure
**Classification:** CWE-306
**Source:** Nuclei Template (`photoprism-unauth-exposure.yaml`)

## Description
PhotoPrism instance is running in public mode with authentication disabled (PHOTOPRISM_AUTH_MODE=public), exposing all photos, albums, GPS locations, face recognition data, and server configuration to unauthenticated users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/config
```

