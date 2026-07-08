# Vulnerability: Unauthenticated Mautic Upgrade.php Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-mautic-upgrade.yaml`)

## Description
Upgrade.php page in Mautic is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/upgrade.php
```

