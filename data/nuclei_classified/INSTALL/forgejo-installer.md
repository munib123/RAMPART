# Vulnerability: Forgejo Installation Page - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`forgejo-installer.yaml`)

## Description
Checks for the presence of a Forgejo Installer Page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

