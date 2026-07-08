# Vulnerability: AzuraCast - Unfinished Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`azuracast-installer.yaml`)

## Description
Detected exposed AzuraCast setup wizard that allows unauthorized superuser account creation.An unfinished AzuraCast installation exposes setup endpoints that enable attackers to create
administrator accounts and gain full control of the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/register
```

