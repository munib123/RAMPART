# Vulnerability: SumoWebTools Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sumowebtools-installer.yaml`)

## Description
SumoWebTools is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

