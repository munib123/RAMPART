# Vulnerability: Matomo Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`matomo-installer.yaml`)

## Description
Matomo is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

