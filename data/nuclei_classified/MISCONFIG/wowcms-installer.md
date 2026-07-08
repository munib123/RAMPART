# Vulnerability: WoW CMS Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`wowcms-installer.yaml`)

## Description
WoW CMS is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

