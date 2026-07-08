# Vulnerability: UVDesk Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`uvdesk-install.yaml`)

## Description
UVDesk is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

