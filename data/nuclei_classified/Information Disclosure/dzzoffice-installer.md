# Nuclei Template: DzzOffice - Installer Page Exposure
**Template ID:** dzzoffice-installer
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`dzzoffice-installer.yaml`)

## Vulnerability Information & PoC

## Description
Detects exposed DzzOffice Installation page.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

