# Vulnerability: PhpGedView Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`phpgedview-installer.yaml`)

## Description
PhpGedView is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

