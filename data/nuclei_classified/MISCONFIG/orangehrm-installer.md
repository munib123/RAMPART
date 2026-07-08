# Vulnerability: OrangeHrm Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`orangehrm-installer.yaml`)

## Description
OrangeHrm is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer/installerUI.php
```

