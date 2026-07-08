# Vulnerability: Gitea Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`gitea-installer.yaml`)

## Description
Gitea is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

