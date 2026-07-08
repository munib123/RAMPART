# Vulnerability: Dolibarr Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`dolibarr-installer.yaml`)

## Description
Dolibarr is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

