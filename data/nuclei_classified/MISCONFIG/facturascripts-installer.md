# Vulnerability: FacturaScripts Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`facturascripts-installer.yaml`)

## Description
FacturaScripts is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

