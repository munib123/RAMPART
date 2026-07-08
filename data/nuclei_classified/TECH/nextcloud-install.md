# Vulnerability: Nextcloud Exposed Installation
**Classification:** TECH
**Source:** Nuclei Template (`nextcloud-install.yaml`)

## Description
Nextcloud installation is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

