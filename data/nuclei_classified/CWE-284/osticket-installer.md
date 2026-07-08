# Vulnerability: osTicket Installer Panel - Detect
**Classification:** CWE-284
**Source:** Nuclei Template (`osticket-installer.yaml`)

## Description
osTicket installer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/upload/setup/install.php
GET {{BaseURL}}/setup/install.php
```

