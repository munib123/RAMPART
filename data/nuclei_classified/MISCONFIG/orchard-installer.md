# Vulnerability: Orchard Setup Wizard - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`orchard-installer.yaml`)

## Description
Orchard is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

