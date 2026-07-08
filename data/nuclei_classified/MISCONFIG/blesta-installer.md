# Vulnerability: Blesta Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`blesta-installer.yaml`)

## Description
Blesta is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/install
```

