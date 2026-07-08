# Vulnerability: Flarum Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`flarum-installer.yaml`)

## Description
Detects exposed Flarum installation pages which could allow unauthorized access or information disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

