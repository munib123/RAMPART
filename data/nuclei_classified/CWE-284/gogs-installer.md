# Vulnerability: Gogs (Go Git Service) - Installer
**Classification:** CWE-284
**Source:** Nuclei Template (`gogs-installer.yaml`)

## Description
Go Git Service installer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

