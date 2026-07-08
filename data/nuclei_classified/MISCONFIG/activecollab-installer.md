# Vulnerability: ActiveCollab Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`activecollab-installer.yaml`)

## Description
Detects exposed ActiveCollab Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

