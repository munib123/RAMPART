# Vulnerability: UVDesk Helpdesk Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`uvdesk-helpdesk-installer.yaml`)

## Description
Detects exposed UVDesk Helpdesk Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#welcome
```

