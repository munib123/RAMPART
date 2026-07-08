# Vulnerability: Jackett - Installer
**Classification:** INSTALL
**Source:** Nuclei Template (`jackett-installer.yaml`)

## Description
Jackett installer exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/configure
```

