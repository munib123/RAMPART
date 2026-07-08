# Vulnerability: GROWI Installer - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`growi-installer.yaml`)

## Description
Checks for the presence of a GROWI Installer.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer
```

