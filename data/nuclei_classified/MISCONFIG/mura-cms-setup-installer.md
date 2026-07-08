# Vulnerability: Mura CMS Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mura-cms-setup-installer.yaml`)

## Description
Detects exposed Mura CMS Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

