# Vulnerability: Fork CMS - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`fork-installer.yaml`)

## Description
Fork CMS installer page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/2
```

