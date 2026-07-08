# Vulnerability: Combodo iTop Installer/Upgrade - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`combodo-itop-installer.yaml`)

## Description
Combodo iTop is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/wizard.php
GET {{BaseURL}}/itop/setup/wizard.php
```

