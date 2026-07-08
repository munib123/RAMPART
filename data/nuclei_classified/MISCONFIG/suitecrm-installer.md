# Vulnerability: SuiteCRM Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`suitecrm-installer.yaml`)

## Description
SuiteCRM is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

