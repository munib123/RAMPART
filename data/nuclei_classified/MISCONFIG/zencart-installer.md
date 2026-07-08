# Vulnerability: Zen Cart Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`zencart-installer.yaml`)

## Description
Zen Cart is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zc_install/index.php
```

