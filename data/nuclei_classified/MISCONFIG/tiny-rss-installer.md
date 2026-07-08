# Vulnerability: Tiny Tiny RSS Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tiny-rss-installer.yaml`)

## Description
Tiny Tiny RSS is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

