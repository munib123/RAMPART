# Vulnerability: Bagisto Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`bagisto-installer.yaml`)

## Description
Bagisto is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer
```

