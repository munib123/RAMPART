# Vulnerability: Saltbo/zpan Installer - Exposure
**Classification:** SALTBO
**Source:** Nuclei Template (`saltbo-zpan-installer.yaml`)

## Description
Detects the exposure of the Saltbo/zpan installer page, which could allow unauthorized setup or reinstallation of the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/system/options/core.email
GET {{BaseURL}}/install
```

