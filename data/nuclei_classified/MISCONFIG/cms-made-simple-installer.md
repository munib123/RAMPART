# Vulnerability: CMS Made Simple Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`cms-made-simple-installer.yaml`)

## Description
Detects exposed CMS Made Simple Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

