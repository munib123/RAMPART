# Vulnerability: TastyIgniter Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tastyigniter-installer.yaml`)

## Description
Detects exposed TastyIgniter Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/
```

