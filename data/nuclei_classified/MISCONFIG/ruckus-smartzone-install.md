# Vulnerability: Ruckus SmartZone Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`ruckus-smartzone-install.yaml`)

## Description
Ruckus SmartZone is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/adminweb/
```

