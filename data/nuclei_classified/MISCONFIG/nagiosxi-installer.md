# Vulnerability: Nagios XI Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`nagiosxi-installer.yaml`)

## Description
Nagios XI is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nagiosxi/install.php
```

