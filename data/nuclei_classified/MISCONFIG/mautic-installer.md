# Vulnerability: Mautic Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mautic-installer.yaml`)

## Description
Mautic is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer
```

