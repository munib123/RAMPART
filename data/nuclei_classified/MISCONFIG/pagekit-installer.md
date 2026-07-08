# Vulnerability: Pagekit Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`pagekit-installer.yaml`)

## Description
Pagekit is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer
```

