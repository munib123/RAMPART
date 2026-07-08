# Vulnerability: Invoice Ninja Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`invoice-ninja-installer.yaml`)

## Description
Detects exposed Invoice Ninja Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

