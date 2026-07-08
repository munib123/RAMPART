# Vulnerability: Businesso Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`businesso-installer.yaml`)

## Description
Businesso is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

