# Vulnerability: Lychee Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`lychee-installer.yaml`)

## Description
Lychee is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

