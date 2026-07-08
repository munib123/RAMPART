# Vulnerability: Chamilo Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`chamilo-installer.yaml`)

## Description
Chamilo is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/main/install/index.php
```

