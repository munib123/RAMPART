# Vulnerability: Permissions Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`permissions-installer.yaml`)

## Description
Permissions Installer is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

