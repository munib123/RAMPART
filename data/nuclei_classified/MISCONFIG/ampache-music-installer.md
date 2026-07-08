# Vulnerability: Ampache Music Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ampache-music-installer.yaml`)

## Description
Ampache Music is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

