# Vulnerability: Shopware Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`shopware-installer.yaml`)

## Description
Shopware is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/public/recovery/install/index.php
```

