# Vulnerability: ICTBroadcast Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ictbroadcast-installer.yaml`)

## Description
ICTBroadcast is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

