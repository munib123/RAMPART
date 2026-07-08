# Vulnerability: Krayin CMS - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`krayin-installer.yaml`)

## Description
Krayin CRM installer page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

