# Vulnerability: Espocrm Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`espocrm-installer.yaml`)

## Description
Espocrm is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

