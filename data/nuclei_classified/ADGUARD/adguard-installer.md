# Vulnerability: AdGuard - Installation
**Classification:** ADGUARD
**Source:** Nuclei Template (`adguard-installer.yaml`)

## Description
AdGuard Installation panel has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.html
```

