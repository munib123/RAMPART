# Vulnerability: phpMyFAQ Installation - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`phpmyfaq-installer.yaml`)

## Description
phpMyFAQ installation is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/index.php
```

