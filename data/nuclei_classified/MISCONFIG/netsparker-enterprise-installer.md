# Vulnerability: Netsparker Enterprise Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`netsparker-enterprise-installer.yaml`)

## Description
Netsparker Enterprise is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizard/database/
```

