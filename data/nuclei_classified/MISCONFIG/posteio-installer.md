# Vulnerability: First Poste.io Configuration Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`posteio-installer.yaml`)

## Description
Poste.io is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/install/server
```

