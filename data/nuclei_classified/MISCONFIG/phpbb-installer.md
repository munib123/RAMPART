# Vulnerability: phpBB Installation File Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`phpbb-installer.yaml`)

## Description
phpBB is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/app.php
```

