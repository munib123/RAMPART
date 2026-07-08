# Vulnerability: ModX CMS - Unfinished Installation
**Classification:** MODX
**Source:** Nuclei Template (`modx-installer.yaml`)

## Description
Detected accessible ModX CMS installation or setup pages that indicated an incomplete installation.An exposed installation interface allowed attackers to complete the setup process and gain administrative access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/
```

