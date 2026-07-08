# Vulnerability: CloudCenter Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`cloudcenter-installer.yaml`)

## Description
CloudCenter is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

