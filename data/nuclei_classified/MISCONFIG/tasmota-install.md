# Vulnerability: Tasmota Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tasmota-install.yaml`)

## Description
Tasmota is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

