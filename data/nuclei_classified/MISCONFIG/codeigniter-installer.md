# Vulnerability: Codeigniter Application Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`codeigniter-installer.yaml`)

## Description
Codeigniter Application is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

