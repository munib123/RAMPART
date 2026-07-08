# Vulnerability: GetSimple CMS - Installer
**Classification:** CWE-284
**Source:** Nuclei Template (`getsimple-installation.yaml`)

## Description
GetSimple CMS installer was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/install.php
```

