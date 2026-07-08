# Vulnerability: NginX Auto Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`nginx-auto-installer.yaml`)

## Description
NginX Auto is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

