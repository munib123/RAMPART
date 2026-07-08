# Vulnerability: JustFans Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`justfans-installer.yaml`)

## Description
Detects exposed JustFans Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

