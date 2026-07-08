# Vulnerability: Acunetix 360 Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`acunetix-360-installer.yaml`)

## Description
Acunetix 360 is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizard/database/
```

