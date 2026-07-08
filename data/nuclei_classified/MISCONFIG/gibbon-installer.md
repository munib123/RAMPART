# Vulnerability: Gibbon Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`gibbon-installer.yaml`)

## Description
Gibbon is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer/install.php
```

