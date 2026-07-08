# Vulnerability: Subrion CMS Web Installer - Exposure
**Classification:** SUBRION
**Source:** Nuclei Template (`subrion-installer.yaml`)

## Description
Subrion CMS Web Installer has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

