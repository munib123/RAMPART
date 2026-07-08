# Vulnerability: Revive Adserver - Exposed Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`revive-adserver-installer.yaml`)

## Description
Detected exposed Revive Adserver installation wizard that allows unauthorized installation and configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/www/admin/install.php?action=welcome
GET {{BaseURL}}/admin/install.php?action=welcome
```

