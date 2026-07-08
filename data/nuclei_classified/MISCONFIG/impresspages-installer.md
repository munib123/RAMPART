# Vulnerability: ImpressPages Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`impresspages-installer.yaml`)

## Description
ImpressPages is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

