# Nuclei Template: PhotoPrism - Unauthenticated Exposure
**Template ID:** photoprism-unauth-exposure
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`photoprism-unauth-exposure.yaml`)

## Vulnerability Information & PoC

## Description
PhotoPrism instance is running in public mode with authentication disabled (PHOTOPRISM_AUTH_MODE=public), exposing all photos, albums, GPS locations, face recognition data, and server configuration to unauthenticated users.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/v1/config
```

## References
- https://docs.photoprism.app/getting-started/config-options/#authentication
- https://docs.photoprism.app/getting-started/
