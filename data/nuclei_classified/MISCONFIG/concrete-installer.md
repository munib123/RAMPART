# Vulnerability: Concrete Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`concrete-installer.yaml`)

## Description
Concrete is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/install
```

