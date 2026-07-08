# Vulnerability: WoWonder Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`wowonder-installer.yaml`)

## Description
Detects exposed WoWonder installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

