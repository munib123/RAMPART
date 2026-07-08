# Vulnerability: Discourse Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`discourse-installer.yaml`)

## Description
Discourse is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/finish-installation/register
```

