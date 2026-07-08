# Vulnerability: Redash Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`redash-installer.yaml`)

## Description
Redash is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

