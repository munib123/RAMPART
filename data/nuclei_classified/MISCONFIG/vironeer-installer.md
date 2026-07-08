# Vulnerability: Vironeer Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`vironeer-installer.yaml`)

## Description
Vironeer is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/information/database
```

