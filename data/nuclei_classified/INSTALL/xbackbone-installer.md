# Vulnerability: XBackBone Installer - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`xbackbone-installer.yaml`)

## Description
Checks for the presence of a XBackBone Installer.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

