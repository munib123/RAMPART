# Vulnerability: EJBCA Enterprise Cloud Configuration Wizard - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ejbca-enterprise-installer.yaml`)

## Description
Detects exposed EJBCA Enterprise Cloud Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

