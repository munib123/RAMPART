# Vulnerability: Snipe-IT Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`snipe-it-installer.yaml`)

## Description
Detects exposed Snipe-IT Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

