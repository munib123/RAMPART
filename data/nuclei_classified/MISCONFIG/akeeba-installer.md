# Vulnerability: Akeeba Backup Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`akeeba-installer.yaml`)

## Description
Akeeba Backup is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installation/index.php
```

