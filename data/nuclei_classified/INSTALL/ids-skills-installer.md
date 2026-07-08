# Vulnerability: IDP Skills Installer - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`ids-skills-installer.yaml`)

## Description
Checks for the presence of an IDS Skills Installer page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/install/main
```

