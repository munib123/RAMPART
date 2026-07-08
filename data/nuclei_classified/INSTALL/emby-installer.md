# Vulnerability: Emby Installation Page - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`emby-installer.yaml`)

## Description
Checks for the presence of a Emby Installer Page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/index.html?start=wizard#!/wizard/wizardstart.html
```

