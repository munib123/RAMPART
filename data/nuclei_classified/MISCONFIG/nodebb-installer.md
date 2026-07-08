# Vulnerability: NodeBB Web Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`nodebb-installer.yaml`)

## Description
NodeBB Web is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

