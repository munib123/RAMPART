# Vulnerability: Webuzo Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`webuzo-installer.yaml`)

## Description
Webuzo is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

