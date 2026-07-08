# Vulnerability: Webasyst Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`webasyst-installer.yaml`)

## Description
Webasyst is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

