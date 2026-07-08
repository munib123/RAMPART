# Vulnerability: Server Monitor Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`server-monitor-installer.yaml`)

## Description
Server Monitor is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

