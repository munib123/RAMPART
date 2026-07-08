# Vulnerability: Dolphin Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`dolphin-installer.yaml`)

## Description
Dolphin is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

