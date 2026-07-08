# Vulnerability: EyouCMS - Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`eyoucms-installer.yaml`)

## Description
EyouCMS installation is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

