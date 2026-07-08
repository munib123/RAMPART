# Vulnerability: DzzOffice - Installer Page Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`dzzoffice-installer.yaml`)

## Description
Detects exposed DzzOffice Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

