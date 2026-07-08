# Vulnerability: YzmCMS - Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`yzmcms-installer.yaml`)

## Description
YzmCMS is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/application/install/index.php
```

