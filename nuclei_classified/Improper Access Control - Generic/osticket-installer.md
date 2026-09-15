# Nuclei Template: osTicket Installer Panel - Detect
**Template ID:** osticket-installer
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`osticket-installer.yaml`)

## Vulnerability Information & PoC

## Description
osTicket installer panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/upload/setup/install.php
GET {{BaseURL}}/setup/install.php
```

