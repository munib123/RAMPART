# Vulnerability: ProcessWire 3.x Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`processwire-installer.yaml`)

## Description
ProcessWire 3.x is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/install.php
```

