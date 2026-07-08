# Vulnerability: Virtual SmartZone Setup Wizard - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`virtual-smartzone-installer.yaml`)

## Description
Detects exposed Virtual SmartZone Installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/adminweb/
```

