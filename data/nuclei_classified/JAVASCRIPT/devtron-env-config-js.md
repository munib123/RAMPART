# Vulnerability: Devtron JavaScript Environment Configuration - Exposure
**Classification:** JAVASCRIPT
**Source:** Nuclei Template (`devtron-env-config-js.yaml`)

## Description
Devtron JavaScript environment configuration file was identified at /dashboard/env-config.js, exposing internal API endpoints and feature flag settings.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard/env-config.js
```

