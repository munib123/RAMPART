# Vulnerability: FreeScout Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`freescout-installer.yaml`)

## Description
FreeScout is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

