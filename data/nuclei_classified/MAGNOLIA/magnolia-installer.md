# Vulnerability: Magnolia CMS Installer
**Classification:** MAGNOLIA
**Source:** Nuclei Template (`magnolia-installer.yaml`)

## Description
Magnolia CMS is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

