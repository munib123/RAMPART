# Vulnerability: Dokploy Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`dokploy-installer.yaml`)

## Description
Dokploy is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/register
```

