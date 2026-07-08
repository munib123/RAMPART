# Vulnerability: Metabase Installer - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`metabase-installer-exposure.yaml`)

## Description
Detected Metabase installer page, allowing unauthorized database setup and configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

